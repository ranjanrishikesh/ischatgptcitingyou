/**
 * SSRF address validation. Destination hostnames are attacker-influenceable (a
 * tenant configures their PostHog host / Sheets endpoint), so before we ever
 * connect we must reject any address that resolves into a private, loopback,
 * link-local, or otherwise-internal range. Pure functions; unit-tested.
 */
import { isIP } from "node:net";

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

function inV4(ip: number, cidrBase: string, bits: number): boolean {
  const base = ipv4ToInt(cidrBase)!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (base & mask);
}

/** Disallowed IPv4 ranges (private, loopback, link-local, CGNAT, reserved, multicast). */
function isDisallowedV4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (n === null) return true; // unparseable -> disallow
  return (
    inV4(n, "0.0.0.0", 8) || // "this network"
    inV4(n, "10.0.0.0", 8) || // private
    inV4(n, "100.64.0.0", 10) || // CGNAT
    inV4(n, "127.0.0.0", 8) || // loopback
    inV4(n, "169.254.0.0", 16) || // link-local
    inV4(n, "172.16.0.0", 12) || // private
    inV4(n, "192.0.0.0", 24) || // IETF protocol assignments
    inV4(n, "192.0.2.0", 24) || // TEST-NET-1
    inV4(n, "192.168.0.0", 16) || // private
    inV4(n, "198.18.0.0", 15) || // benchmarking
    inV4(n, "198.51.100.0", 24) || // TEST-NET-2
    inV4(n, "203.0.113.0", 24) || // TEST-NET-3
    inV4(n, "224.0.0.0", 4) || // multicast
    inV4(n, "240.0.0.0", 4) // reserved + broadcast
  );
}

function hx(s: string): number {
  return /^[0-9a-f]{1,4}$/.test(s) ? parseInt(s, 16) : NaN;
}

/**
 * Expand any textual IPv6 (compressed `::`, embedded dotted v4, expanded form)
 * to its 8 numeric hextets. Returns null on malformed input. Range checks are
 * then done numerically — NEVER on the textual first-hextet, which misses every
 * non-dotted spelling of an embedded IPv4 (the source of real SSRF bypasses).
 */
export function expandV6(ip: string): number[] | null {
  let s = ip.toLowerCase().split("%")[0]!; // strip zone id
  // Convert an embedded dotted-quad tail (::ffff:127.0.0.1) into two hextets.
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0 && s.slice(lastColon + 1).includes(".")) {
    const v4 = ipv4ToInt(s.slice(lastColon + 1));
    if (v4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  let hextets: number[];
  if (halves.length === 2) {
    const tail = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    hextets = [...head.map(hx), ...Array(missing).fill(0), ...tail.map(hx)];
  } else {
    hextets = head.map(hx);
  }
  if (hextets.length !== 8 || hextets.some((h) => Number.isNaN(h) || h < 0 || h > 0xffff)) {
    return null;
  }
  return hextets;
}

/**
 * Disallowed IPv6. Rejects loopback/unspecified, ULA, link-local, multicast,
 * documentation/Teredo/discard ranges, and — critically — ALL IPv4-mapped,
 * IPv4-compatible, and NAT64 forms (in EVERY notation), since these tunnel to an
 * embedded IPv4 and no legitimate public destination presents as one.
 */
function isDisallowedV6(ip: string): boolean {
  const h = expandV6(ip);
  if (!h) return true;
  const highSixZero = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0;
  if (h.every((x) => x === 0)) return true; // :: unspecified
  if (highSixZero && h[6] === 0 && h[7] === 1) return true; // ::1 loopback
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    return true; // IPv4-mapped ::ffff:0:0/96 (any notation)
  }
  if (highSixZero) return true; // IPv4-compatible ::/96 (deprecated) + any ::x:y
  if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0) return true; // NAT64 64:ff9b::/96
  if ((h[0]! & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((h[0]! & 0xfe00) === 0xfc00) return true; // ULA fc00::/7
  if ((h[0]! & 0xff00) === 0xff00) return true; // multicast ff00::/8
  if (h[0] === 0x2001 && h[1] === 0x0db8) return true; // documentation 2001:db8::/32
  if (h[0] === 0x2001 && (h[1]! & 0xfe00) === 0x0000) return true; // IETF/Teredo 2001::/23
  if (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0) return true; // discard 100::/64
  return false;
}

/** True if `ip` (a literal v4 or v6 address) must NOT be connected to. */
export function isDisallowedIp(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return isDisallowedV4(ip);
  if (v === 6) return isDisallowedV6(ip);
  return true; // not a literal IP -> disallow (callers pass resolved IPs)
}
