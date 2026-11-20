/**
 * Install `globalThis.soroauthExplain`, the gate a page calls before it signs.
 *
 * This runs in the *page's* world (the content script injects it as a module),
 * which is what lets it define a global the page's signing flow can await. It
 * needs nothing from `chrome.*`: everything it loads is a web-accessible
 * extension resource, addressed relative to this module's own URL.
 *
 * The passkey example (`examples/browser-passkey/explain-gate.js`) calls
 * `globalThis.soroauthExplain.confirm(...)` before it asks the authenticator to
 * sign, and proceeds only on an explicit approval. A page that has not opted
 * into the gate is unaffected: no global, no interception.
 */

import { loadCore } from "./core.js";
import { buildReport } from "./report.js";
import { confirmReport } from "./overlay.js";
import { signEntryWithPasskey } from "./signing.js";

/**
 * The gate object the page awaits.
 *
 * `confirm` resolves `true` only after an explicit approval click; every other
 * outcome (reject, Escape, backdrop, a core error) resolves `false` or throws,
 * and the example treats both as refusal.
 */
const explanation = {
  version: "0.1.0",
  async confirm({ entry, validUntilLedger, currentLedger }) {
    const core = await loadCore();
    const report = buildReport({ core, entryXdr: entry, validUntilLedger, currentLedger });
    return confirmReport({ report });
  },

  /**
   * Sign the explained entry with a passkey and return the signed entry.
   *
   * The same report is rendered, and the payload hash shown in it is the hash
   * of the bytes the authenticator is asked to sign. A refusal rejects the
   * promise and no partial entry is returned. The page supplies the public key
   * it registered with the account contract; the extension does not store keys.
   */
  async sign({
    entry,
    validUntilLedger,
    currentLedger,
    networkPassphrase,
    publicKeyHex,
    forAddress = "",
    rpId,
    credentialId,
    allowCredentials,
  }) {
    const core = await loadCore();
    const report = buildReport({ core, entryXdr: entry, validUntilLedger, currentLedger });
    const { payloadHex } = core.preimage(entry, validUntilLedger, networkPassphrase);
    return signEntryWithPasskey({
      core,
      entryXdr: entry,
      validUntilLedger,
      networkPassphrase,
      publicKeyHex,
      expectedPayloadHex: payloadHex,
      forAddress,
      rpId,
      credentialId,
      allowCredentials,
      confirm: ({ payloadHex: shown }) => confirmReport({ report, payloadHex: shown }),
    });
  },
};

globalThis.soroauthExplain = explanation;
