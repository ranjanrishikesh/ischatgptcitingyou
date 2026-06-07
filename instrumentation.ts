/**
 * Next.js instrumentation — runs once per server instance at startup.
 *
 * Wires the hosted posture assertion into BOOT so a misconfigured hosted deploy
 * (missing KMS / Stripe / Redis / INGEST_ID_PEPPER, owner DB role, or RLS not
 * forced) FAILS CLOSED by refusing to start — rather than throwing 500s inside
 * live requests and leaking config state. Self-host mode only warns.
 */
export async function register(): Promise<void> {
  // Don't probe during the build phase; only at real server start.
  if (process.env.NEXT_PHASE === "phase-production-build") return;
  // Load the node-only probe ONLY in the node runtime, via a dedicated module —
  // so the bundler never pulls postgres/net into a non-node (edge) bundle.
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./instrumentation.node"); // throws in hosted mode if posture is down -> no boot
  }
}
