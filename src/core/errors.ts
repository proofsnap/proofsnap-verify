// Thrown when the check cannot run here (unsupported runtime, a ZIP feature or
// size this verifier cannot unpack, out of memory). It is never a statement
// about the evidence: callers show "could not be checked", not "invalid".
export class CannotVerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CannotVerifyError";
  }
}
