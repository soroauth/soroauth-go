/**
 * The error thrown when a call into the signing core fails.
 *
 * The Go module reports failures as `{ ok: false, error: "..." }`. The wrapper
 * turns every one of those into a thrown {@link SoroauthError} whose `message`
 * is the module's own message, which already names the operation and the
 * protocol rule it enforced (for example, "source-account credentials carry no
 * signature payload"). Callers therefore never branch on a numeric code, and a
 * stack trace points at the call that failed.
 */
export class SoroauthError extends Error {
  override readonly name = "SoroauthError";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    // Preserve the prototype chain when compiled down and subclassed; without
    // this, `instanceof SoroauthError` can fail across some transpilations.
    Object.setPrototypeOf(this, SoroauthError.prototype);
  }
}
