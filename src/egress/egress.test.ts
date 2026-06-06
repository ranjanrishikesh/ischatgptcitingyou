import { describe, it, expect } from "vitest";
import { isDisallowedIp } from "./ssrf";
import { safeFetch, SsrfError } from "./safeFetch";

describe("isDisallowedIp", () => {
  it("blocks private / loopback / link-local / CGNAT / reserved IPv4", () => {
    for (const ip of [
      "0.0.0.0",
      "10.0.0.5",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.169.254", // cloud metadata
      "172.16.5.4",
      "192.168.1.1",
      "224.0.0.1",
      "255.255.255.255",
    ]) {
      expect(isDisallowedIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPv4", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "93.184.216.34"]) {
      expect(isDisallowedIp(ip), ip).toBe(false);
    }
  });

  it("blocks loopback / ULA / link-local / multicast / reserved IPv6", () => {
    for (const ip of [
      "::1",
      "::",
      "fe80::1",
      "fc00::1",
      "fd12:3456::1",
      "ff02::1",
      "2001:db8::1", // documentation
      "2001::1", // Teredo / IETF protocol 2001::/23
      "100::1", // discard-only
    ]) {
      expect(isDisallowedIp(ip), ip).toBe(true);
    }
  });

  it("blocks IPv4-mapped / -compatible / NAT64 in EVERY notation (SSRF bypass class)", () => {
    for (const ip of [
      "::ffff:10.0.0.1", // dotted mapped
      "::ffff:7f00:1", // hex mapped = 127.0.0.1
      "::ffff:a9fe:a9fe", // hex mapped = 169.254.169.254 (metadata)
      "0:0:0:0:0:ffff:7f00:1", // fully expanded mapped
      "::ffff:8.8.8.8", // even public-looking mapped is rejected outright
      "::7f00:1", // IPv4-compatible (deprecated)
      "64:ff9b::a9fe:a9fe", // NAT64 wrapping metadata
      "64:ff9b::7f00:1", // NAT64 wrapping loopback
    ]) {
      expect(isDisallowedIp(ip), ip).toBe(true);
    }
  });

  it("allows genuine public IPv6 and blocks non-IPs", () => {
    expect(isDisallowedIp("2606:4700:4700::1111")).toBe(false);
    expect(isDisallowedIp("2a00:1450:4001:81b::200e")).toBe(false);
    expect(isDisallowedIp("not-an-ip")).toBe(true);
    expect(isDisallowedIp("example.com")).toBe(true);
  });
});

describe("safeFetch guards", () => {
  it("rejects non-https before any network call", async () => {
    await expect(safeFetch("http://example.com/x")).rejects.toBeInstanceOf(SsrfError);
  });

  it("rejects invalid urls", async () => {
    await expect(safeFetch("not a url")).rejects.toBeInstanceOf(SsrfError);
  });

  it("rejects non-443 ports", async () => {
    await expect(safeFetch("https://example.com:8080/x")).rejects.toBeInstanceOf(SsrfError);
  });

  it("rejects literal internal IPs (v4 + bracketed v6) without DNS", async () => {
    await expect(safeFetch("https://127.0.0.1/x")).rejects.toBeInstanceOf(SsrfError);
    await expect(safeFetch("https://[::1]/x")).rejects.toBeInstanceOf(SsrfError);
    await expect(safeFetch("https://169.254.169.254/latest/meta-data/")).rejects.toBeInstanceOf(SsrfError);
  });
});
