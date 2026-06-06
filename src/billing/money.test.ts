import { describe, it, expect } from "vitest";
import {
  dollars,
  eventsToMicros,
  microsToEvents,
  formatUsd,
  rechargeChargeMicros,
  microsToStripeCents,
  eventCostMicrosNumber,
  FREE_GRANT_MICROS,
  AUTO_RECHARGE_THRESHOLD_MICROS,
  AUTO_RECHARGE_TARGET_MICROS,
  MICRO_PER_EVENT,
} from "./money.js";

describe("money", () => {
  it("dollars -> micro-dollars", () => {
    expect(dollars(1)).toBe(1_000_000n);
    expect(dollars(20)).toBe(20_000_000n);
    expect(dollars(19.99)).toBe(19_990_000n);
    expect(dollars(0.0001)).toBe(100n); // one event
  });

  it("pricing: $1 == 10,000 events", () => {
    expect(eventsToMicros(10_000)).toBe(dollars(1));
    expect(MICRO_PER_EVENT).toBe(100n);
    expect(microsToEvents(dollars(1))).toBe(10_000n);
    expect(microsToEvents(-5n)).toBe(0n);
  });

  it("formatUsd", () => {
    expect(formatUsd(20_000_000n)).toBe("$20.00");
    expect(formatUsd(19_990_000n)).toBe("$19.99");
    expect(formatUsd(0n)).toBe("$0.00");
    expect(formatUsd(-1_500_000n)).toBe("-$1.50");
  });

  it("policy constants", () => {
    expect(FREE_GRANT_MICROS).toBe(1_000_000n);
    expect(AUTO_RECHARGE_THRESHOLD_MICROS).toBe(5_000_000n);
    expect(AUTO_RECHARGE_TARGET_MICROS).toBe(20_000_000n);
  });

  it("auto-recharge: trigger at <= $5, top up to $20", () => {
    expect(rechargeChargeMicros(dollars(6))).toBe(0n); // above threshold, no charge
    expect(rechargeChargeMicros(dollars(5))).toBe(dollars(15)); // at threshold -> to $20
    expect(rechargeChargeMicros(dollars(4))).toBe(dollars(16));
    expect(rechargeChargeMicros(dollars(0))).toBe(dollars(20));
    // overshoot: balance went negative before cron caught it -> clear deficit too
    expect(rechargeChargeMicros(-dollars(2))).toBe(dollars(22));
  });

  it("stripe cents round UP (never undercharge)", () => {
    expect(microsToStripeCents(dollars(15))).toBe(1500);
    expect(microsToStripeCents(1n)).toBe(1); // 0.0001 cents rounds up to 1 cent
    expect(microsToStripeCents(0n)).toBe(0);
  });

  it("eventCostMicrosNumber validates and never lets float reach Redis", () => {
    expect(eventCostMicrosNumber(0)).toBe(0);
    expect(eventCostMicrosNumber(1)).toBe(100);
    expect(eventCostMicrosNumber(10_000)).toBe(1_000_000); // $1
    expect(() => eventCostMicrosNumber(1.5)).toThrow(/integer/);
    expect(() => eventCostMicrosNumber(-1)).toThrow(/negative/);
    expect(() => eventCostMicrosNumber(NaN)).toThrow(/integer/);
    expect(() => eventCostMicrosNumber(1e15)).toThrow(/too large/); // 1e15*100 > 2^53
  });
});
