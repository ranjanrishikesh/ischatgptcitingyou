/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Server-only / node-native packages: keep external so the bundler never tries
  // to resolve their node builtins (e.g. postgres -> `net`/`tls`) into a
  // non-node bundle, and so better-auth's internal kysely adapter (kysely
  // peer-version mismatch) isn't bundled.
  serverExternalPackages: [
    "better-auth",
    "@better-auth/kysely-adapter",
    "kysely",
    "postgres",
    "@aws-sdk/client-kms",
    "@upstash/redis",
    "stripe",
    "undici",
  ],
  // Security headers are applied here at the platform edge. Per-route auth is
  // re-checked inside Server Actions / route handlers — middleware is routing,
  // NOT a security boundary (cf. CVE-2025-29927).
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
