import { describe, it, expect } from "vitest";
import { validateBounds } from "./autoRecharge";
import { dollars } from "./money";

describe("auto-recharge bounds (card-drain guard)", () => {
  it("accepts the locked default ($5 -> $20)", () => {
    expect(() => validateBounds(dollars(5), dollars(20))).not.toThrow();
  });

  it("rejects a card-draining target", () => {
    expect(() => validateBounds(dollars(5), dollars(5_000_000))).toThrow(/target too high/);
  });

  it("rejects a constantly-firing high threshold", () => {
    expect(() => validateBounds(dollars(1000), dollars(2000))).toThrow(/threshold too high/);
  });

  it("rejects target <= threshold and negative threshold", () => {
    expect(() => validateBounds(dollars(20), dollars(5))).toThrow(/target must exceed/);
    expect(() => validateBounds(dollars(10), dollars(10))).toThrow(/target must exceed/);
    expect(() => validateBounds(-dollars(1), dollars(20))).toThrow(/>= 0/);
  });

  it("rejects too-small a gap", () => {
    expect(() => validateBounds(dollars(10), dollars(10) + dollars(1) / 2n)).toThrow(/gap too small/);
  });
});
