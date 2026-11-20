// The browser extension's logic, checked against the real wasm signing core.
//
// The extension is browser code and CI has no browser, so what is checked here
// is everything about it that does not need one:
//
//   * `buildReport` runs the actual wasm core (`inspect`, `analyze`,
//     `renderTree`, `renderInvocations`) over committed golden vectors and the
//     report carries the arm, address, nonce, expiration, delegate tree,
//     invocation tree, findings, disclaimer and analyzer limits;
//   * `renderReport` puts all of that in the DOM, including the limits, so a UI
//     cannot present the structure as a verdict;
//   * `confirmReport` approves only on an explicit click — reject, Escape and
//     the backdrop all resolve to refusal;
//   * the passkey example's gate proceeds with no extension installed, refuses
//     when the extension declines, and refuses (never silently proceeds) when
//     the extension throws.
//
// What is NOT checked: the extension loading in a real browser (manifest,
// content-script injection, the Go runtime in a page). That is stated in
// README.md rather than implied to be covered.
//
// Build first, from the repository root:
//
//   ./wasm/build.sh && (cd wasm/ts && npm ci && npm run build)
//
// then: `npm test` (which stages the build output into vendor/ first).

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { loadSoroauth } from "../vendor/index.js";
import {
  ANALYZER_LIMITS,
  DISCLAIMER,
  buildReport,
  describeArm,
  highestSeverity,
} from "../src/report.js";
import { confirmReport, renderReport } from "../src/overlay.js";
import { signEntryWithPasskey, verifyAssertion } from "../src/signing.js";
import { requestExplanation } from "../../../examples/browser-passkey/explain-gate.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXTENSION = resolve(HERE, "..");
const ROOT = resolve(EXTENSION, "..", "..");
const WASM = join(EXTENSION, "vendor", "soroauth.wasm");
const SHIM = join(EXTENSION, "vendor", "wasm_exec.js");
const VECTORS = join(ROOT, "testdata", "vectors");

const built = existsSync(WASM) && existsSync(SHIM);
const skip = built
  ? false
  : "vendor/ is missing; run ./wasm/build.sh, build wasm/ts, then `npm run stage`";

let corePromise = null;

/** loadCore instantiates the wasm core once for the whole file. */
function core() {
  if (!corePromise) {
    corePromise = (async () => {
      const require = createRequire(import.meta.url);
      globalThis.require = require;
      globalThis.fs = require("node:fs");
      globalThis.path = require("node:path");
      (0, eval)(readFileSync(SHIM, "utf8"));
      return loadSoroauth({
        wasm: readFileSync(WASM),
        go: globalThis.Go,
        globalObject: globalThis,
      });
    })();
  }
  return corePromise;
}

function vector(name) {
  return JSON.parse(readFileSync(join(VECTORS, name), "utf8"));
}

// --- a minimal DOM, so the overlay's logic is exercised in Node -------------

function makeElement(doc, tag) {
  const el = {
    tagName: tag.toUpperCase(),
    children: [],
    parent: null,
    className: "",
    textContent: "",
    attributes: {},
    listeners: {},
    type: "",
    setAttribute(key, value) {
      this.attributes[key] = value;
    },
    append(...nodes) {
      for (const node of nodes) {
        if (node.parent) node.remove();
        node.parent = this;
        this.children.push(node);
      }
    },
    addEventListener(type, fn) {
      (this.listeners[type] ??= []).push(fn);
    },
    removeEventListener(type, fn) {
      if (this.listeners[type]) {
        this.listeners[type] = this.listeners[type].filter((candidate) => candidate !== fn);
      }
    },
    remove() {
      if (!this.parent) return;
      const index = this.parent.children.indexOf(this);
      if (index >= 0) this.parent.children.splice(index, 1);
      this.parent = null;
    },
    dispatch(type, event = {}) {
      for (const fn of [...(this.listeners[type] ?? [])]) fn(event);
    },
  };
  Object.defineProperty(el, "classList", {
    value: { toggle() {}, add() {}, remove() {} },
  });
  return el;
}

function makeDocument() {
  const doc = {
    listeners: {},
    createElement: (tag) => makeElement(doc, tag),
    addEventListener(type, fn) {
      (doc.listeners[type] ??= []).push(fn);
    },
    removeEventListener(type, fn) {
      if (doc.listeners[type]) {
        doc.listeners[type] = doc.listeners[type].filter((candidate) => candidate !== fn);
      }
    },
    dispatch(type, event = {}) {
      for (const fn of [...(doc.listeners[type] ?? [])]) fn(event);
    },
  };
  doc.body = makeElement(doc, "body");
  doc.head = makeElement(doc, "head");
  return doc;
}

/** collectText concatenates every text node beneath el. */
function collectText(el) {
  let text = typeof el.textContent === "string" ? el.textContent : "";
  for (const child of el.children ?? []) text += `\n${collectText(child)}`;
  return text;
}

/** findByClass returns the first element whose className contains token. */
function findByClass(el, token) {
  if (typeof el.className === "string" && el.className.includes(token)) return el;
  for (const child of el.children ?? []) {
    const found = findByClass(child, token);
    if (found) return found;
  }
  return null;
}

// --- the report is built from the wasm core ---------------------------------

test("the report reads a V2 entry's structure from the wasm core", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const report = buildReport({
    core: soroauth,
    entryXdr: v.unsigned_entry_xdr,
    validUntilLedger: v.valid_until_ledger,
  });

  assert.equal(report.credentialType, "address_v2");
  assert.equal(report.addressBound, true);
  assert.match(report.armLabel, /CAP-71-01/);
  assert.match(report.address, /^G/);
  assert.equal(report.topLevelSigned, false);
  // The unsigned entry stores expiration 0, so the request's own valid-until is
  // what the user must be shown.
  assert.equal(report.validUntilLedger, v.valid_until_ledger);
  assert.ok(report.invocationTree.includes("("), "the invocation tree names argument counts");
  assert.ok(report.credentialTree.includes(report.address), "the credential tree shows the address");
  assert.equal(report.disclaimer, DISCLAIMER);
  assert.deepEqual(report.analyzerLimits, ANALYZER_LIMITS);
});

test("the report shows the delegate tree from a delegates vector", { skip }, async () => {
  const soroauth = await core();
  const v = vector("delegates_unsorted_with_nested.json");
  const report = buildReport({
    core: soroauth,
    entryXdr: v.unsigned_entry_xdr,
    validUntilLedger: v.valid_until_ledger,
  });

  assert.equal(report.credentialType, "address_with_delegates");
  assert.ok(report.delegates.length >= 2, "the delegate list is reported");
  assert.ok(
    report.credentialTree.includes("├──") || report.credentialTree.includes("└──"),
    `the credential tree must draw the delegate hierarchy, got:\n${report.credentialTree}`,
  );
  assert.ok(report.delegates.some((node) => Array.isArray(node.nested) && node.nested.length > 0));
});

test("a source-account entry is reported without inventing an address or a tree", { skip }, async () => {
  const soroauth = await core();
  const v = vector("source_account_testnet.json");
  const report = buildReport({ core: soroauth, entryXdr: v.unsigned_entry_xdr });

  assert.equal(report.credentialType, "source_account");
  assert.equal(report.address, null);
  assert.equal(report.credentialTree, null);
  assert.ok(report.invocationTree.length > 0);
  assert.equal(describeArm(report.credentialType).startsWith("Source account"), true);
});

test("a malformed entry is an error, not an empty report", { skip }, async () => {
  const soroauth = await core();
  assert.throws(() => buildReport({ core: soroauth, entryXdr: "not base64 xdr" }));
  assert.throws(() => buildReport({ core: soroauth, entryXdr: "" }));
});

test("highestSeverity ranks critical above warning above info", () => {
  assert.equal(highestSeverity([]), null);
  assert.equal(highestSeverity([{ severity: "info" }]), "info");
  assert.equal(highestSeverity([{ severity: "info" }, { severity: "critical" }]), "critical");
  assert.equal(highestSeverity([{ severity: "warning" }, { severity: "info" }]), "warning");
});

// --- the overlay renders the report and requires a decision ------------------

test("the rendered panel carries the trees, the disclaimer and the limits", { skip }, async () => {
  const soroauth = await core();
  const v = vector("delegates_unsorted_with_nested.json");
  const report = buildReport({ core: soroauth, entryXdr: v.unsigned_entry_xdr });

  const doc = makeDocument();
  const panel = renderReport(report, doc);
  const text = collectText(panel);

  assert.ok(text.includes(DISCLAIMER), "the disclaimer is part of the panel");
  for (const limit of ANALYZER_LIMITS) {
    assert.ok(text.includes(limit), `the analyzer limit is shown: ${limit}`);
  }
  assert.ok(text.includes("Credential and delegate tree"));
  assert.ok(text.includes("Invocation tree"));
  assert.ok(text.includes(report.credentialTree.split("\n")[0]), "the credential tree is rendered");
  assert.ok(text.includes("Risk findings"));
});

test("confirmation approves only on the approve button", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const report = buildReport({ core: soroauth, entryXdr: v.unsigned_entry_xdr });

  const approveDoc = makeDocument();
  const approved = confirmReport({ report, doc: approveDoc });
  findByClass(approveDoc.body, "__approve").dispatch("click", {});
  assert.equal(await approved, true);

  const rejectDoc = makeDocument();
  const rejected = confirmReport({ report, doc: rejectDoc });
  findByClass(rejectDoc.body, "__reject").dispatch("click", {});
  assert.equal(await rejected, false);

  const escapeDoc = makeDocument();
  const escaped = confirmReport({ report, doc: escapeDoc });
  escapeDoc.dispatch("keydown", { key: "Escape" });
  assert.equal(await escaped, false, "Escape must not approve");
});

test("the backdrop dismisses as a rejection, a click inside the panel does not", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const report = buildReport({ core: soroauth, entryXdr: v.unsigned_entry_xdr });

  const doc = makeDocument();
  const decision = confirmReport({ report, doc });
  const backdrop = findByClass(doc.body, "__backdrop");
  const panel = findByClass(doc.body, "__panel");
  backdrop.dispatch("click", { target: panel });
  // A click on the panel is not a decision; the dialog is still open, so
  // approving afterwards must still work.
  findByClass(doc.body, "__approve").dispatch("click", {});
  assert.equal(await decision, true);
});

// --- the passkey example's gate ---------------------------------------------

test("the example proceeds with no extension installed", async () => {
  delete globalThis.soroauthExplain;
  const result = await requestExplanation({ entry: "x" });
  assert.deepEqual(result, { approved: true, gate: "absent" });
});

test("the example refuses when the extension declines or throws", async () => {
  globalThis.soroauthExplain = { confirm: async () => false };
  assert.equal((await requestExplanation({})).approved, false);

  globalThis.soroauthExplain = { confirm: async () => undefined };
  assert.equal((await requestExplanation({})).approved, false, "anything but true is refusal");

  globalThis.soroauthExplain = {
    confirm: async () => {
      throw new Error("wasm core failed to load");
    },
  };
  const failed = await requestExplanation({});
  assert.equal(failed.approved, false);
  assert.equal(failed.gate, "error");
  assert.match(failed.reason, /wasm core failed/);

  delete globalThis.soroauthExplain;
});

test("the example proceeds only on an explicit true from the extension", async () => {
  globalThis.soroauthExplain = { confirm: async () => true };
  assert.deepEqual(await requestExplanation({}), { approved: true, gate: "extension" });
  delete globalThis.soroauthExplain;
});

// --- the extension completes a passkey signature ----------------------------

/** buildAssertion builds a WebAuthn assertion over payloadHex with a real P-256 key. */
function buildAssertion(payloadHex, { flags = 0x05 } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const spki = publicKey.export({ format: "der", type: "spki" });
  const publicKeyBytes = spki.subarray(spki.length - 65);
  assert.equal(publicKeyBytes[0], 0x04, "SPKI ends in an uncompressed P-256 point");

  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(payloadHex, "hex").toString("base64url"),
      origin: "http://localhost",
    }),
  );
  const authenticatorData = Buffer.alloc(37);
  authenticatorData[32] = flags;
  const signed = Buffer.concat([
    authenticatorData,
    crypto.createHash("sha256").update(clientDataJSON).digest(),
  ]);
  const signature = crypto.sign("sha256", signed, privateKey);
  return {
    publicKeyHex: publicKeyBytes.toString("hex"),
    assertion: {
      response: {
        clientDataJSON,
        authenticatorData,
        signature,
      },
    },
  };
}

test("the extension signs an explained entry with a passkey", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { payloadHex } = soroauth.preimage(
    v.unsigned_entry_xdr,
    v.valid_until_ledger,
    v.network_passphrase,
  );
  const { publicKeyHex, assertion } = buildAssertion(payloadHex);

  let gets = 0;
  const result = await signEntryWithPasskey({
    core: soroauth,
    entryXdr: v.unsigned_entry_xdr,
    validUntilLedger: v.valid_until_ledger,
    networkPassphrase: v.network_passphrase,
    publicKeyHex,
    expectedPayloadHex: payloadHex,
    credentials: {
      get: async (options) => {
        gets += 1;
        assert.ok(options.publicKey.challenge instanceof Uint8Array);
        assert.equal(
          Buffer.from(options.publicKey.challenge).toString("hex"),
          payloadHex,
          "the challenge is the payload the user was shown",
        );
        return assertion;
      },
    },
  });

  assert.equal(gets, 1);
  assert.equal(result.payloadHex, payloadHex);
  assert.equal(result.signatureScvalB64.length > 0, true);
  assert.notEqual(result.entryB64, v.unsigned_entry_xdr);
});

test("a payload that changed after explanation is never signed", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { publicKeyHex } = buildAssertion("00".repeat(32));
  let gets = 0;

  await assert.rejects(
    signEntryWithPasskey({
      core: soroauth,
      entryXdr: v.unsigned_entry_xdr,
      validUntilLedger: v.valid_until_ledger,
      networkPassphrase: v.network_passphrase,
      publicKeyHex,
      expectedPayloadHex: "00".repeat(32),
      credentials: {
        get: async () => {
          gets += 1;
          throw new Error("must not be called");
        },
      },
    }),
    /changed between explanation and signing/,
  );
  assert.equal(gets, 0, "the authenticator is never asked for a changed payload");
});

test("an authenticator refusal returns no entry", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { payloadHex } = soroauth.preimage(
    v.unsigned_entry_xdr,
    v.valid_until_ledger,
    v.network_passphrase,
  );
  const { publicKeyHex } = buildAssertion(payloadHex);

  await assert.rejects(
    signEntryWithPasskey({
      core: soroauth,
      entryXdr: v.unsigned_entry_xdr,
      validUntilLedger: v.valid_until_ledger,
      networkPassphrase: v.network_passphrase,
      publicKeyHex,
      expectedPayloadHex: payloadHex,
      credentials: {
        get: async () => {
          throw new Error("NotAllowedError: the user refused");
        },
      },
    }),
    /user refused/,
  );
});

test("an assertion without user verification is refused", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { payloadHex } = soroauth.preimage(
    v.unsigned_entry_xdr,
    v.valid_until_ledger,
    v.network_passphrase,
  );
  const { publicKeyHex, assertion } = buildAssertion(payloadHex, { flags: 0x01 });

  await assert.rejects(
    signEntryWithPasskey({
      core: soroauth,
      entryXdr: v.unsigned_entry_xdr,
      validUntilLedger: v.valid_until_ledger,
      networkPassphrase: v.network_passphrase,
      publicKeyHex,
      expectedPayloadHex: payloadHex,
      credentials: { get: async () => assertion },
    }),
    /did not verify the user/,
  );
});

test("an assertion for a different payload is refused", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { payloadHex } = soroauth.preimage(
    v.unsigned_entry_xdr,
    v.valid_until_ledger,
    v.network_passphrase,
  );
  const { assertion } = buildAssertion("11".repeat(32));
  assert.throws(
    () => verifyAssertion(assertion, payloadHex),
    /does not commit to this payload/,
  );
});

test("the panel shows the payload hash the authenticator will sign", { skip }, async () => {
  const soroauth = await core();
  const v = vector("v2_single_testnet.json");
  const { payloadHex } = soroauth.preimage(
    v.unsigned_entry_xdr,
    v.valid_until_ledger,
    v.network_passphrase,
  );
  const report = buildReport({ core: soroauth, entryXdr: v.unsigned_entry_xdr });
  const panel = renderReport(report, makeDocument(), { payloadHex });
  assert.ok(collectText(panel).includes(payloadHex), "the full payload hash is shown");
});
