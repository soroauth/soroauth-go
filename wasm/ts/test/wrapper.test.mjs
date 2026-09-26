// Wrapper tests, run under jsdom.
//
// These exercise the TypeScript layer itself: that a raw {ok:false} envelope
// becomes a thrown SoroauthError with the module's message, that a missing
// field is caught rather than returned as undefined, and that the fetch path
// reports a bad response. They use a fake Go runtime and a minimal, valid wasm
// module -- they are about the wrapper, not the signing logic. The signing
// logic is covered by the integration test and by wasm/parity.mjs.
//
// jsdom is used on purpose: this is the surface a browser sees, including the
// script-tag global.

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { JSDOM } from "jsdom";

import { loadSoroauth, SoroauthError, SoroauthGlobal } from "../dist/index.js";

// The smallest valid wasm module: a magic number and a version. It instantiates
// to an empty instance, which is all a fake Go runtime needs.
const MINIMAL_WASM = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

/** A Go class whose run() installs bindings on the window it is given. */
function goThatInstalls(window, bindings) {
  return class {
    constructor() {
      this.importObject = {};
    }
    async run() {
      window.soroauth = bindings;
    }
  };
}

const okBindings = {
  preimage: () => ({ ok: true, preimageXdr: "PRE", payloadHex: "aa".repeat(32) }),
  payload: () => ({ ok: true, payloadHex: "bb".repeat(32) }),
  writeSignature: () => ({ ok: true, entryB64: "SIGNED" }),
  authorizeWithSeed: (_entry, _until, _net, _seed, forAddress) => ({
    ok: true,
    entryB64: forAddress === "" ? "SIGNED-DEFAULT" : `SIGNED-${forAddress}`,
  }),
};

let dom;

before(() => {
  dom = new JSDOM("<!doctype html><html><body></body></html>", {
    runScripts: "outside-only",
  });
});

beforeEach(() => {
  // Each test starts with no bindings installed, so a test that expects a
  // timeout cannot be satisfied by the previous test's module.
  delete dom.window.soroauth;
});

after(() => {
  dom.window.close();
});

describe("loadSoroauth", () => {
  it("returns a typed API that passes arguments through", async () => {
    const api = await loadSoroauth({
      wasm: MINIMAL_WASM,
      go: goThatInstalls(dom.window, okBindings),
      globalObject: dom.window,
    });

    assert.deepEqual(api.preimage("ENTRY", 42, "Test SDF Network ; September 2015"), {
      preimageXdr: "PRE",
      payloadHex: "aa".repeat(32),
    });
    assert.equal(api.payload("PRE"), "bb".repeat(32));
    assert.equal(api.writeSignature("ENTRY", 42, "net", "GADDR", "SCVAL"), "SIGNED");
    // A missing forAddress defaults to the empty string, the "top-level node"
    // convention the Go binding uses.
    assert.equal(api.authorizeWithSeed("ENTRY", 42, "net", "seed"), "SIGNED-DEFAULT");
    assert.equal(
      api.authorizeWithSeed("ENTRY", 42, "net", "seed", "GADDR"),
      "SIGNED-GADDR",
    );
  });

  it("throws SoroauthError carrying the module's message", async () => {
    const bindings = {
      ...okBindings,
      preimage: () => ({ ok: false, error: "credentials are source-account, which carry no signature payload" }),
    };
    const api = await loadSoroauth({
      wasm: MINIMAL_WASM,
      go: goThatInstalls(dom.window, bindings),
      globalObject: dom.window,
    });

    assert.throws(
      () => api.preimage("ENTRY", 1, "net"),
      (err) => {
        assert.ok(err instanceof SoroauthError);
        assert.match(err.message, /source-account/);
        assert.match(err.message, /^preimage: /);
        return true;
      },
    );
  });

  it("rejects a success envelope missing a required field", async () => {
    const bindings = {
      ...okBindings,
      // ok:true but no preimageXdr -- a malformed module, not a protocol error.
      preimage: () => ({ ok: true, payloadHex: "cc".repeat(32) }),
    };
    const api = await loadSoroauth({
      wasm: MINIMAL_WASM,
      go: goThatInstalls(dom.window, bindings),
      globalObject: dom.window,
    });

    assert.throws(() => api.preimage("E", 1, "net"), /did not return preimageXdr/);
  });

  it("loads wasm from a URL via fetch", async () => {
    const seen = [];
    const api = await loadSoroauth({
      wasm: "https://example.test/soroauth.wasm",
      go: goThatInstalls(dom.window, okBindings),
      globalObject: dom.window,
      fetchImpl: async (url) => {
        seen.push(url);
        return {
          ok: true,
          status: 200,
          arrayBuffer: async () => MINIMAL_WASM.buffer,
        };
      },
    });
    assert.deepEqual(seen, ["https://example.test/soroauth.wasm"]);
    assert.equal(api.payload("PRE"), "bb".repeat(32));
  });

  it("reports a non-200 fetch as a SoroauthError", async () => {
    await assert.rejects(
      loadSoroauth({
        wasm: "https://example.test/missing.wasm",
        go: goThatInstalls(dom.window, okBindings),
        globalObject: dom.window,
        fetchImpl: async () => ({ ok: false, status: 404 }),
      }),
      /HTTP 404/,
    );
  });

  it("times out with a clear message when the module never installs bindings", async () => {
    class NeverInstalls {
      constructor() {
        this.importObject = {};
      }
      async run() {
        // Deliberately does nothing.
      }
    }
    await assert.rejects(
      loadSoroauth({
        wasm: MINIMAL_WASM,
        go: NeverInstalls,
        globalObject: dom.window,
        timeoutMs: 30,
      }),
      /timed out after 30ms/,
    );
  });
});

describe("script-tag surface", () => {
  it("exposes the same API as globalThis.Soroauth", () => {
    assert.ok(SoroauthGlobal);
    assert.equal(SoroauthGlobal.loadSoroauth, loadSoroauth);
    assert.equal(SoroauthGlobal.SoroauthError, SoroauthError);
    assert.equal(globalThis.Soroauth, SoroauthGlobal);
  });
});
