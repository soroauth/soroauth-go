/*
 * libsoroauth.h — Stable C ABI for the soroauth signing core.
 *
 * This is the committed, hand-written public interface. Every language binding
 * builds against this header, not the one cgo generates. The two must agree;
 * bindings_c_header_test.go enforces that every //export in soroauth.go has a
 * declaration here, and vice-versa.
 *
 * ABI contract:
 *   - Every function that returns char* returns a heap-allocated UTF-8 JSON
 *     envelope (or a plain string for SoroauthVersion). The caller releases
 *     it with SoroauthFree.
 *   - Increment SOROAUTH_ABI_VERSION (and the value SoroauthAbiVersion
 *     returns) on any breaking ABI change: a removed function, a changed
 *     signature, or a changed envelope schema.
 *   - Adding a new function is not a breaking change: the version stays.
 *
 * Threading contract:
 *   - Every function in this header is safe to call concurrently from any
 *     thread, including simultaneous calls to the same function.
 *   - Each returned char* is owned by the caller. Free it with SoroauthFree
 *     exactly once. SoroauthFree(NULL) is a no-op. Reading or freeing the
 *     same pointer from more than one thread without the caller's own
 *     synchronisation is a use-after-free in the caller's code.
 *   - No SoroauthInit entry point; no library-wide lock; no OS-thread
 *     affinity.
 *   - The library is not signal-safe. Calls from a POSIX signal handler
 *     are not supported.
 *   - The full contract lives in bindings/c/THREADING.md; the Go-side
 *     evidence is the test TestABIThreadingContract at the repo root.
 */

#ifndef LIBSOROAUTH_H
#define LIBSOROAUTH_H

#ifdef __cplusplus
extern "C" {
#endif

/* Monotonic ABI version. Incremented on any breaking change. */
#define SOROAUTH_ABI_VERSION 1

/* Return the ABI version as a runtime-queryable integer. */
int SoroauthAbiVersion(void);

/* Return the library version string. Free with SoroauthFree. */
char* SoroauthVersion(void);

/* Release a string returned by any function in this ABI. NULL is a no-op. */
void SoroauthFree(char* ptr);

/*
 * Build the HashIdPreimage and its 32-byte payload for an address-credential
 * entry. Returns a JSON envelope with preimageXdr and payloadHex.
 */
char* SoroauthPreimage(const char* entryB64,
                       long long   validUntilLedger,
                       const char* networkPassphrase);

/*
 * Hash an already-built preimage to its 32-byte payload.
 * Returns a JSON envelope with payloadHex.
 */
char* SoroauthPayload(const char* preimageB64);

/*
 * Write an externally produced signature ScVal onto every credential node
 * whose address matches. Returns a JSON envelope with entryB64.
 */
char* SoroauthWriteSignature(const char* entryB64,
                             long long   validUntilLedger,
                             const char* networkPassphrase,
                             const char* forAddress,
                             const char* signatureScvalB64);

/*
 * Sign an entry with a single 32-byte ed25519 seed (hex).
 * Returns a JSON envelope with entryB64.
 */
char* SoroauthAuthorizeWithSeed(const char* entryB64,
                                long long   validUntilLedger,
                                const char* networkPassphrase,
                                const char* seedHex,
                                const char* forAddress);

/*
 * Sign an entry with one or more comma-separated ed25519 seeds (hex).
 * Returns a JSON envelope with entryB64.
 */
char* SoroauthAuthorizeWithSeeds(const char* entryB64,
                                 long long   validUntilLedger,
                                 const char* networkPassphrase,
                                 const char* seedsCSV,
                                 const char* forAddress);

/*
 * Report an entry's structure as JSON (soroauth.EntryInfo).
 * Returns a JSON envelope with infoJson.
 */
char* SoroauthInspect(const char* entryB64);

/*
 * Run the risk analyzer and return its findings as JSON.
 * Returns a JSON envelope with findingsJson.
 */
char* SoroauthAnalyze(const char* entryB64, long long currentLedger);

/*
 * Render the invocation tree as ASCII.
 * Returns a JSON envelope with tree.
 */
char* SoroauthRenderInvocations(const char* entryB64);

/*
 * Render the credential/delegate tree as ASCII.
 * Returns a JSON envelope with tree.
 */
char* SoroauthRenderTree(const char* entryB64);

#ifdef __cplusplus
}
#endif

#endif /* LIBSOROAUTH_H */
