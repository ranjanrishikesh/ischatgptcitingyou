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
- **Bearer revocation latency**: the drain resolves a source from a short (≤5s) in-process
  cache holding its bearer hash + status, so a rotated/revoked bearer keeps authenticating for
  up to that window per warm instance. Bounded + documented. When rotation/revocation ships
  (M4) it must also publish a cross-process invalidation (per-process cache delete is not enough
  for a multi-instance hosted deploy).
- **Ingest IP trust**: the pre-auth rate limiter keys on the platform-trusted client IP
  (`x-real-ip` / right-most XFF hop), never the spoofable left-most XFF. Self-host operators
  behind a different proxy topology must ensure the same trusted-hop assumption.
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
