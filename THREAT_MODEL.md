# Threat model

Goal, in the founder's words: **no data gets leaked.** This documents what that means,
what we enforce, and — honestly — where the limits are.

## Assets

1. **Destination credentials** (PostHog/Mixpanel/Amplitude keys, Google refresh tokens).
2. **Tenant identity & config** (who routes where).
3. **Usage counters / balance** (billing integrity).

We deliberately do **not** hold a fourth asset most pipelines do: **customer traffic data**.
It is classified in memory and discarded. The cheapest data to protect is data you never store.

## Trust boundaries

internet → ingest endpoint · browser → control plane · worker → destinations · app → secret store.

## Controls (enforced, not aspirational)

- **Two-failure isolation**: app scoping + **FORCE RLS** (fail-closed GUC) + per-tenant DEK
  with **independently-derived AAD**. Any single bug is caught by the next wall.
- **Boot self-test** refuses to start if a missing org context returns rows.
- **Hosted posture assertion** refuses to start if KEK isn't real KMS, the runtime role owns
  the tables, or FORCE RLS is off.
- **Least-privilege credentials**: prefer write-only ingest keys → a stolen key can at worst
  write junk, not read the customer's analytics.
- **Egress is hostile-by-default** (M2+): resolve-and-pin destination hostnames, reject
  internal IP ranges, no redirect following, HTTPS only — destination URLs are attacker-
  influenceable, so SSRF is treated as a first-class risk.
- **No-leak logging**: `Secret<T>` + `redactForLog` + CI secret-scan of src and (planned)
  build logs. Outbound error paths capture method+host+status only — never headers/body.
- **Append-only money ledger**, idempotent credits, single-flight recharge.
- **Tamper-evident audit**: sensitive actions append to a hash-chained, append-only
  `audit_log` (identifiers + action types only, never secret values); `verifyAuditChain`
  detects any edit/deletion.
- **Crypto-shredding erasure**: deleting an org destroys its wrapped per-tenant DEK, making
  every stored ciphertext — including database backups/WAL — permanently undecryptable. The
  only erasure that reaches immutable backups.
- **Cross-tenant CI gate**: the isolation self-test proves A/B isolation, missing-GUC fails
  closed, `ingest_resolve` is id-scoped, destinations are isolated, and a cross-org route is
  rejected by the DB trigger — run against a real Postgres in CI.
- **Remaining GA gate**: hosted must pass an independent third-party penetration test of the
  custody path before holding any real customer credential. (External; not code.)

## Honest limits

- **Self-host `file` KEK is a weaker guarantee.** The key sits next to the ciphertext, so a
  DB dump *plus* the key file = full recovery. "Your secrets never touch our servers" is true;
  "nothing is decryptable from a DB dump" is **not** true in this mode. Self-host is encouraged
  to use its own KMS/Vault (`KEK_PROVIDER=kms`). Hosted mode rejects file-KEK at boot.
- **Google refresh token is read+write**, not write-only. It can read/modify sheets the app
  created. It is treated as the highest-value stored secret (`drive.file` scope, append-only
  writes, revoke-on-anomaly) — but we will not market the Google path as "junk-only".
- **No auto-recharge cap** (a product decision). A bot storm could run up charges; we mitigate
  with per-charge email + spike alerts, not a hard ceiling. Documented so it's a choice, not a
  surprise.
- **Credential revocation SLA (multi-instance hosted)**: caches are in-process, so rotating a
  source bearer / disabling a source / rotating a destination credential busts only the local
  instance. Fleet-wide staleness is bounded by the cache TTLs: **≤5s** for a source bearer/status,
  **≤30s** for a destination credential. The rotation APIs call the local invalidators; a
  cross-process invalidation (Redis pub/sub or a versioned key) is deferred hardening (M6) — until
  then the TTLs above are the revocation SLA. For instant fleet-wide revocation, restart instances
  or rely on the upstream key being independently revoked at the destination.
- **Ingest IP trust**: the pre-auth rate limiter keys on the platform-trusted client IP
  (`x-real-ip` / right-most XFF hop), never the spoofable left-most XFF. Self-host operators
  behind a different proxy topology must ensure the same trusted-hop assumption.
- **Reconcile endpoint** (`/api/cron/reconcile`): guarded only by `CRON_SECRET` (constant-time
  compare, fail-closed when unset) with no per-route rate limit, so the secret must be high
  entropy (`openssl rand -base64 32`), never human-chosen. Blast radius of a leaked secret is
  bounded — flushes are idempotent and recharge is single-flighted + balance-re-checked — so a
  caller can generate load, not charges. The bigger risk is **cadence loss**: auto-recharge runs
  only from this cron, so its freshness is exported at `/api/health` for external alerting.
- **Self-host supply chain**: "no phone-home" stops *us*, not a poisoned dependency. The
  deployable app ships a default-deny egress policy + pinned lockfile + SBOM (M-later), but a
  self-hoster running untrusted deps is outside our control.

## STRIDE quick map

| | Threat | Primary control |
|---|---|---|
| S | spoofed ingest batch | per-source bearer (constant-time) + self-validating MAC'd ingestId |
| T | tampered payload / replay | AEAD auth tag; per-batch content-hash idempotency gate on the drain (Redis SETNX, dedups Vercel at-least-once redelivery so a batch is metered once) |
| R | repudiated charge | append-only ledger + Stripe idempotency |
| I | cross-tenant disclosure | FORCE RLS + per-tenant DEK + AAD (two-failure) |
| D | recharge/DoS amplification | edge IP limiter before I/O; O(1) forged-id rejection |
| E | privilege escalation | non-owner runtime role; authz re-checked in Server Actions, not middleware |
