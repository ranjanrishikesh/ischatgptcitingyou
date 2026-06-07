import { describe, it, expect } from "vitest";
import { stableStringify } from "./audit";

describe("stableStringify (audit canonicalization)", () => {
  it("is independent of object key order (jsonb round-trip safe)", () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
    expect(stableStringify({ zebra: 1, apple: 2 })).toBe('{"apple":2,"zebra":1}');
  });

  it("sorts nested object keys too", () => {
    expect(stableStringify({ x: { d: 1, c: 2 } })).toBe(stableStringify({ x: { c: 2, d: 1 } }));
  });

  it("preserves array order and scalars", () => {
    expect(stableStringify([3, 1, 2])).toBe("[3,1,2]");
    expect(stableStringify({ n: null, s: "x", b: true })).toBe('{"b":true,"n":null,"s":"x"}');
  });
});
