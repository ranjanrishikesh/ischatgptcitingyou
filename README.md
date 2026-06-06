# is ChatGPT citing you?

A pipeline that captures **AI-crawler / bot page-view traffic** to your website and
forwards it to **your own** analytics destination (PostHog, Mixpanel, Amplitude, or a
Google Sheet). It answers one question: *which of your pages are ChatGPT, Claude,
Perplexity, Gemini & co. actually reading* — so you can write more of what AI cites you for.

**We store none of your traffic.** Events are classified in memory, forwarded, and
forgotten. The only data at rest is your account, your (encrypted) destination
credential, and a usage counter.

## Two modes, one codebase

Selected at boot via `DEPLOY_MODE`:

- **`self_host`** (default) — you deploy it (Vercel/your server), your secrets stay in
  your env, no external SaaS dependency, no billing. Runs against any Postgres.
- **`hosted`** — our multi-tenant platform. Sign up, connect a source and a destination,
  pay per forwarded event. Boots **only** if the full security posture is satisfied
  (real KMS, FORCE RLS, per-tenant DEKs, Stripe + Redis configured).

## Pipeline (hosted)

```
your site ─► Vercel Log Drain (NDJSON) ─► /api/drain/{ingestId}
                                              │ auth (bearer, constant-time)
                                              │ classify bot/AI in memory
                                              │ debit credits (1 Redis op)
                                              ▼
                              your PostHog / Mixpanel / Amplitude / Sheet
                                   (we forward, then discard. nothing stored.)
```

## Billing (hosted)

- Prepaid **dollar** balance, metered by events. **$1 = 10,000 events** ($0.0001/event).
- Money is integer **micro-dollars** + bigint (never float). See `src/billing/money.ts`.
- **$1 free** on signup. Auto-recharge: at **≤ $5**, charge the saved card up to **$20**
  (email sent on every charge). One-time packs: **$50 / $100**.
- Hot meter in Redis; reconciled to an append-only Postgres ledger by cron — the request
  path makes **zero** Postgres/Stripe calls.

## Security spine (M0 — built)

- **Envelope encryption**: KEK (KMS hosted / file self-host) → per-tenant DEK → per-field
  AES-256-GCM with AAD bound to `{tenantId, secretType, recordId}`. (`src/crypto/`)
- **`Secret<T>`** wrapper: credentials can't leak via log/JSON/template/inspect.
- **FORCE Row Level Security** on every tenant table, keyed on a per-tx GUC; **missing
  context = zero rows (fail closed)**. (`src/db/`)
- **Boot guards**: `isolation:selftest` proves cross-tenant isolation; `posture:assert`
  refuses to start hosted mode if any control is down.
- Least privilege: store only **write-only** destination keys where the vendor allows it.

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the honest limits (esp. self-host file-KEK).

## Develop

```sh
cp .env.example .env.local
npm install
npm run typecheck
npm test              # pure-logic units (money, Secret, crypto round-trips)
npm run dev
```

Database (needs Postgres):
```sh
npm run db:generate && npm run db:migrate   # as owner role
npm run db:rls                              # apply FORCE RLS + policies
npm run isolation:selftest                  # prove fail-closed isolation
```

## Status

| Milestone | What | State |
|-----------|------|-------|
| M0 | Crypto + isolation + billing spine | **done** |
| M1 | Secure ingest endpoint | next |
| M2 | PostHog destination | |
| M3 | Google Sheets (OAuth) | |
| M4 | Sign-in + self-host config UI | |
| M5 | Hosted custody machinery | gated |
| M6 | Hosted GA (audit, pentest) | gated |
