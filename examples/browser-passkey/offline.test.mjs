// The offline demo's proof: a real browser, a virtual authenticator, and a
// hard failure on any request made after the page has loaded.
//
// The page is served from a local static server. Once `window.__offlineReady`
// is true every asset needed to sign is already in the browser; from that point
// the context routes every request to the violation list and aborts it, so a
// stray analytics call, font fetch, source map or SDK import cannot pass
// unnoticed. A count assertion would be weaker: it would still allow the first
// unexpected request.
//
// Run:
//   ./examples/browser-passkey/build-offline.sh
//   cd examples/browser-passkey && npm ci && npx playwright install chromium
//   node offline.test.mjs

import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const VECTOR = JSON.parse(
  readFileSync(join(ROOT, "testdata", "vectors", "v2_single_testnet.json"), "utf8"),
);
// The vector's top-level credential address. writeSignature targets a node by
// address; this page asks the operator for it rather than guessing.
const WALLET = "GC33NWBJFXQSQMD3AMHTFEFT36IH5ZBG24L5RZMQGKO2SPBTVB74VZI5";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".map": "application/json",
};

function serve() {
  return new Promise((resolveServer, reject) => {
    const server = createServer((req, res) => {
      const path = decodeURIComponent((req.url ?? "/").split("?")[0]);
      const relative = normalize(path).replace(/^(\.\.[/\\])+/, "");
      const file = join(HERE, relative === "/" ? "offline.html" : relative);
      if (!file.startsWith(HERE)) {
        res.writeHead(403).end("forbidden");
        return;
      }
      try {
        const body = readFileSync(file);
        res.writeHead(200, {
          "content-type": MIME[extname(file)] ?? "application/octet-stream",
          "cache-control": "no-store",
        });
        res.end(body);
      } catch {
        res.writeHead(404).end("not found");
      }
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

const server = await serve();
const { port } = server.address();

let failures = 0;
const check = (condition, description) => {
  if (condition) {
    console.log(`ok   - ${description}`);
  } else {
    failures++;
    console.error(`FAIL - ${description}`);
  }
};

const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const page = await context.newPage();

  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });

  // Start at localhost, not 127.0.0.1: WebAuthn RP IDs are domain names, and an
  // IP literal is not a valid one.
  await page.goto(`http://localhost:${port}/offline.html`);
  await page.waitForFunction(
    () => window.__offlineReady === true || window.__offlineStartupError,
    null,
    { timeout: 20_000 },
  );
  const startupError = await page.evaluate(() => window.__offlineStartupError);
  check(!startupError, `the offline signing core loaded${startupError ? `: ${startupError}` : ""}`);

  // From here on, any request is a failure. Route before interacting so a
  // request started by the registration or signing flow is caught too.
  const violations = [];
  await context.route("**/*", (route) => {
    violations.push(route.request().url());
    return route.abort();
  });

  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.click("#register");
  try {
    await page.waitForFunction(
      () =>
        document
          .getElementById("log")
          .textContent.includes("registered a passkey"),
      null,
      { timeout: 20_000 },
    );
  } catch (error) {
    console.error(`registration log: ${await page.textContent("#log")}`);
    console.error(`console errors: ${consoleErrors.join(" | ")}`);
    throw error;
  }
  check(true, "a passkey was registered through the page");

  await page.fill("#entry", VECTOR.unsigned_entry_xdr);
  await page.fill("#wallet", WALLET);
  await page.fill("#network", VECTOR.network_passphrase);
  await page.fill("#validUntil", String(VECTOR.valid_until_ledger));
  await page.click("#sign");

  await page.waitForFunction(
    () =>
      typeof window.__offlineSignedEntry === "string" ||
      document.getElementById("log").textContent.includes("signing failed"),
    null,
    { timeout: 30_000 },
  );

  const logText = await page.textContent("#log");
  const signed = await page.evaluate(() => window.__offlineSignedEntry ?? "");
  check(
    !logText.includes("signing failed"),
    `signing completed${logText.includes("signing failed") ? `: ${logText}` : ""}`,
  );
  check(signed.length > 0, "the page produced a signed entry");
  check(
    signed !== VECTOR.unsigned_entry_xdr,
    "the signed entry differs from the unsigned input",
  );
  check(
    Buffer.from(signed, "base64").length > 0,
    "the output is valid base64",
  );

  check(
    violations.length === 0,
    `the page made no request after load${violations.length ? `: ${violations.join(", ")}` : ""}`,
  );
  check(
    consoleErrors.length === 0,
    `no console errors${consoleErrors.length ? `: ${consoleErrors.join(" | ")}` : ""}`,
  );
} finally {
  await browser.close();
  server.close();
}

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log("all offline checks passed");
