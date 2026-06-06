/**
 * Secret<T> — a value that refuses to leak through the usual exfiltration paths:
 * console.log, JSON.stringify, string templates, util.inspect, error messages.
 *
 * The single most common real-world credential leak is not a broken cipher — it
 * is a secret that got string-interpolated into a log line or an error. Wrapping
 * every credential in Secret makes that a compile-and-runtime nuisance instead of
 * a silent disaster. You must call .expose() to get the value, which greps easily
 * in review and is the only place the plaintext appears.
 */

const REDACTED = "[REDACTED]";

export class Secret<T = string> {
  // Private field — not enumerable, not reachable via Object.entries/spread.
  readonly #value: T;

  constructor(value: T) {
    this.#value = value;
  }

  /** The ONLY way to read the underlying value. Greppable on purpose. */
  expose(): T {
    return this.#value;
  }

  /** Map the inner value without ever exposing it to the caller's scope twice. */
  map<U>(fn: (v: T) => U): Secret<U> {
    return new Secret(fn(this.#value));
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  // node's console.log / util.inspect hook
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED;
  }
}

export function isSecret(v: unknown): v is Secret<unknown> {
  return v instanceof Secret;
}

/**
 * Deep-redact a plain object for logging: any Secret becomes "[REDACTED]", and
 * any key that *looks* like a credential is redacted by name as a backstop for
 * raw strings that should have been wrapped but weren't.
 */
const SENSITIVE_KEY_RE =
  /(secret|token|password|passwd|api[_-]?key|authorization|bearer|credential|private[_-]?key|refresh[_-]?token|client[_-]?secret|webhook)/i;

export function redactForLog(input: unknown, depth = 0): unknown {
  if (depth > 6) return "[truncated]";
  if (isSecret(input)) return REDACTED;
  if (input === null || typeof input !== "object") return input;
  if (Array.isArray(input)) return input.map((v) => redactForLog(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY_RE.test(k) ? REDACTED : redactForLog(v, depth + 1);
  }
  return out;
}
