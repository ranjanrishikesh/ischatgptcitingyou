/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // better-auth is server-only; keep it external so webpack doesn't try to bundle
  // its internal kysely adapter (which has a kysely peer-version mismatch).
  serverExternalPackages: ["better-auth", "@better-auth/kysely-adapter", "kysely"],
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
