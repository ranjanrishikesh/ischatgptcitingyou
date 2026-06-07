/**
 * Money. All balances are integer **micro-dollars** (µ$), where 1 µ$ = $0.000001.
 *
 * Why micro-dollars and bigint: the per-event price ($0.0001) is finer than a
 * cent, and floating point must NEVER touch money. bigint integer math is exact
 * and has no rounding drift. Display conversion to dollars happens only at the
 * very edge (formatUsd), never in arithmetic.
 *
 * Pricing (locked): $1 = 10,000 forwarded events  =>  1 event = $0.0001 = 100 µ$.
 */

export const MICRO_PER_DOLLAR = 1_000_000n;
/** Cost of forwarding one billable event. $0.0001. */
export const MICRO_PER_EVENT = 100n;
export const EVENTS_PER_DOLLAR = 10_000n;

/** Convert a dollar amount (e.g. 19.99) to integer micro-dollars. */
export function dollars(amount: number): bigint {
  if (!Number.isFinite(amount)) throw new RangeError("dollars(): non-finite amount");
  // Round at the micro-dollar boundary so float input (e.g. 0.1) can't drift.
  return BigInt(Math.round(amount * Number(MICRO_PER_DOLLAR)));
}

/** Micro-dollars consumed by N events. */
export function eventsToMicros(events: number | bigint): bigint {
  const n = typeof events === "bigint" ? events : BigInt(Math.trunc(events));
  if (n < 0n) throw new RangeError("eventsToMicros(): negative events");
  return n * MICRO_PER_EVENT;
}

/** How many whole events a balance can still pay for (floor). */
export function microsToEvents(micros: bigint): bigint {
  return micros <= 0n ? 0n : micros / MICRO_PER_EVENT;
}

/** Render micro-dollars as a "$X.XX" string for UI/email. Display only. */
export function formatUsd(micros: bigint): string {
  const neg = micros < 0n;
  const abs = neg ? -micros : micros;
  const cents = (abs * 100n) / MICRO_PER_DOLLAR; // floor to cents
  const whole = cents / 100n;
  const frac = cents % 100n;
  return `${neg ? "-" : ""}$${whole}.${frac.toString().padStart(2, "0")}`;
}

// --- Billing policy constants (locked with the founder) --------------------

/** Free credit granted on signup. $1 = 10,000 events. */
export const FREE_GRANT_MICROS = dollars(1);
/** Auto-recharge fires when balance is at or below this. $5. */
export const AUTO_RECHARGE_THRESHOLD_MICROS = dollars(5);
/** Auto-recharge tops the balance back up to this. $20. */
export const AUTO_RECHARGE_TARGET_MICROS = dollars(20);
/** One-time purchasable packs. */
export const PACKS_MICROS = [dollars(50), dollars(100)] as const;

/**
 * Amount to charge so a balance at/below the threshold returns to the target.
 * Handles overshoot (balance went slightly negative before the cron caught it)
 * by charging enough to clear the deficit too. Returns 0 if no recharge is due.
 */
export function rechargeChargeMicros(
  currentBalanceMicros: bigint,
  thresholdMicros: bigint = AUTO_RECHARGE_THRESHOLD_MICROS,
  targetMicros: bigint = AUTO_RECHARGE_TARGET_MICROS,
): bigint {
  if (currentBalanceMicros > thresholdMicros) return 0n;
  const charge = targetMicros - currentBalanceMicros;
  return charge > 0n ? charge : 0n;
}

/**
 * Stripe charges in cents (integer). Convert micro-dollars to cents, rounding
 * UP so we never undercharge a fractional cent (the customer's favour costs us,
 * not them). Used only when actually hitting Stripe.
 */
export function microsToStripeCents(micros: bigint): number {
  if (micros <= 0n) return 0;
  const cents = (micros + (MICRO_PER_DOLLAR / 100n - 1n)) / (MICRO_PER_DOLLAR / 100n);
  if (cents > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("charge too large");
  return Number(cents);
}

/**
 * Micro-dollar cost of N events as a validated JS number, for the Redis hot
 * meter (which works in integers). Rejects non-integer, negative, and counts
 * large enough that the cost would lose precision past Number.MAX_SAFE_INTEGER.
 * Float must never reach Redis as a debit amount.
 */
export function eventCostMicrosNumber(events: number): number {
  if (!Number.isInteger(events)) throw new RangeError("eventCost: events must be an integer");
  if (events < 0) throw new RangeError("eventCost: negative events");
  const cost = BigInt(events) * MICRO_PER_EVENT;
  if (cost > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("eventCost: batch too large");
  return Number(cost);
}
