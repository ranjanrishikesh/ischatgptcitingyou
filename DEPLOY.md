# Production deploy runbook (hosted mode)

Everything between this repo and a live, paying-customers deployment — in order.
Each step says **where to click** and **what value to copy where**. Self-host is
at the bottom (it's much shorter).

> **Two decisions to make before starting** (they change the steps):
>
> 1. **Vercel plan.** The Hobby (free) plan's terms prohibit commercial use —
>    anything that charges money. To take payments you need **Vercel Pro
>    ($20/mo)**. Alternative: launch a **free beta** first (skip Stripe, leave
>    billing off) and upgrade when you start charging. Pro also lifts the cron
>    limit, so the reconcile schedule in `vercel.json` can go back to `*/5`.
> 2. **The pentest gate.** Our own rule (THREAT_MODEL.md): hosted mode must not
>    hold a real customer's analytics credential until an independent
>    penetration test of the custody path passes. Friends-and-family beta with
>    test keys is fine before that.

## Accounts you need

| Service | Used for | Free tier OK? |
|---|---|---|
| Vercel | runs the app | Pro needed once charging money |
| Neon (neon.tech) | Postgres database | yes to start |
| Upstash (upstash.com) | Redis hot billing meter | yes |
| AWS | KMS key that encrypts customer credentials | ~$1/mo per key |
| Stripe | payments | pay-per-transaction |
| Resend (resend.com) | billing + password-reset emails | yes (100/day) |
| Google Cloud | optional — "export to Google Sheet" feature | yes |
| Domain registrar | your production domain | — |

## 1. Generate the app's own secrets (3 of them)

In any terminal, run `openssl rand -base64 32` three times. Save the outputs as:

- `BETTER_AUTH_SECRET` — signs login sessions
- `CRON_SECRET` — protects the billing-reconcile endpoint
- `INGEST_ID_PEPPER` — lets us reject forged ingest URLs without a DB lookup

## 2. Postgres (Neon)

1. Create a project → copy the connection string. That user is the **owner**
   role → it becomes `DATABASE_OWNER_URL`.
2. Create a second, **unprivileged** role for the app (SQL editor):
   ```sql
   CREATE ROLE app_runtime LOGIN PASSWORD '<strong password>';
   ```
   Its connection string (same host/db, user `app_runtime`) becomes
   `DATABASE_URL`. Set `RUNTIME_DB_ROLE=app_runtime`.
   *Why two?* Row-level security — the wall between tenants — is silently
   inert for a table's owner. The app must never connect as one.
3. From your laptop, with both URLs in `.env.local`:
   ```sh
   pnpm db:migrate          # create tables (as owner)
   pnpm db:rls              # turn on FORCE row-level security
   pnpm isolation:selftest  # PROVE tenant isolation fails closed
   ```
   Do not continue until the self-test passes.

## 3. Redis (Upstash)

Create a Redis database (region close to your Vercel region) → copy
**UPSTASH_REDIS_REST_URL** and **UPSTASH_REDIS_REST_TOKEN** from the REST API
section.

## 4. AWS KMS (encrypts customer credentials)

1. AWS Console → KMS → Create key → Symmetric, encrypt/decrypt. Copy the key
   ARN → `KMS_KEY_ID`. Note the region → `AWS_REGION`.
2. IAM → create a user `ischatgptcitingyou-app` with **no console access**,
   attach an inline policy allowing only `kms:Encrypt`, `kms:Decrypt`,
   `kms:GenerateDataKey` **on that one key ARN**.
3. Create an access key for it → `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`.
4. Set `KEK_PROVIDER=kms`. (Hosted mode refuses to boot with anything else.)

## 5. Stripe

1. Activate the account (business details) to get **live** keys.
2. Developers → API keys: copy `STRIPE_SECRET_KEY` (sk_live…) and
   `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (pk_live…).
3. Developers → Webhooks → Add endpoint:
   - URL: `https://<your-domain>/api/stripe/webhook`
   - Events: `payment_intent.succeeded`, `setup_intent.succeeded`
   - Copy the signing secret (whsec…) → `STRIPE_WEBHOOK_SECRET`.

## 6. Resend (email)

1. Add and verify your domain (they give you DNS records to add at your
   registrar).
2. Create an API key → `RESEND_API_KEY`. Set
   `EMAIL_FROM=noreply@<your-domain>`.
   Hosted mode requires this: the email-on-every-charge is the safety net for
   uncapped auto-recharge, and password reset depends on it.

## 7. Google Cloud (only if you want the Sheets destination)

1. Create a project → enable the **Google Sheets API**.
2. OAuth consent screen → External → app name + support email. Add **no**
   logo and only the `drive.file` scope (it's non-sensitive — no verification
   review needed). **Publish to "In production"** — in Testing mode, every
   connected Sheet silently breaks after 7 days (refresh tokens expire).
3. Credentials → Create OAuth client → Web application → authorized redirect
   URI exactly: `https://<your-domain>/api/oauth/google/callback`
4. Copy `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`.

## 8. Vercel

1. Project `ischatgptcitingyou` → Settings → Git → connect the GitHub repo
   (deploys happen on push to `main`).
2. Settings → Domains → add your domain, follow the DNS instructions.
3. Settings → Environment Variables → **Production** — set ALL of:

   | Variable | Value from |
   |---|---|
   | `DEPLOY_MODE` | `hosted` |
   | `DATABASE_URL` | step 2 (app_runtime) |
   | `DATABASE_OWNER_URL` | step 2 (owner) — used only by migrations |
   | `RUNTIME_DB_ROLE` | `app_runtime` |
   | `KEK_PROVIDER` | `kms` |
   | `KMS_KEY_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | step 4 |
   | `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | step 3 |
   | `BETTER_AUTH_SECRET` | step 1 |
   | `BETTER_AUTH_URL` | `https://<your-domain>` |
   | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | step 5 |
   | `CRON_SECRET` | step 1 |
   | `RESEND_API_KEY`, `EMAIL_FROM` | step 6 |
   | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | step 7 (optional) |
   | `INGEST_ID_PEPPER` | step 1 |

4. Deploy (push to `main`). The app **asserts its security posture at boot**
   and refuses to start if anything above is missing or unsafe — check the
   Vercel function logs if the deployment errors.

## 9. Turn on the frequent billing reconcile (GitHub)

Vercel Hobby only allows the daily backstop cron, so a GitHub Action calls the
reconcile endpoint every 30 minutes. In the GitHub repo → Settings → Secrets
and variables → Actions:

1. Secret `CRON_SECRET` — same value as on Vercel
2. Secret `APP_URL` — `https://<your-domain>`
3. Variable `RECONCILE_ENABLED` — `true` (**set this last**)

On Vercel **Pro**, skip this and set `vercel.json` back to `*/5 * * * *`.

## 10. Watch it

- Point a free uptime monitor (e.g. UptimeRobot) at
  `https://<your-domain>/api/health`. It returns **503 when billing
  reconciliation has stalled** (>45 min) — that's the "auto-recharge is not
  running" alarm. The 45-minute threshold assumes the 30-minute GitHub
  schedule from step 9; if you change one, change the other
  (`STALE_AFTER_MS` in `app/api/health/route.ts`).
- Smoke test: sign up → dashboard → create source → connect PostHog → add the
  drain (below) → events appear in PostHog → balance ticks down.

## What a customer does (for your docs/onboarding email)

1. Sign up → Dashboard → **Create source** → copy the Drain URL + Bearer token
   (shown once).
2. In *their* Vercel team: Team Settings → Log Drains → Add:
   - Sources: **Static** + **Edge/Function** (request logs), NDJSON format
   - Endpoint: the Drain URL
   - Custom header: `Authorization: Bearer <token>`
3. Connect a destination (their PostHog key or a Google Sheet) and create a
   route. AI-crawler visits start appearing in their analytics.

## Launch gates (don't skip)

- [ ] Vercel Pro before the first real charge (Hobby ToS prohibits commercial use)
- [ ] Independent pentest of the custody path before holding real customer
      credentials (the M6 gate in THREAT_MODEL.md)
- [ ] Terms of Service + Privacy Policy pages linked from signup (required by
      Stripe's terms and EU/India consumer law once you charge)

---

## Self-host (the short version)

```sh
cp .env.example .env.local   # fill: DATABASE_URL(+OWNER), keep DEPLOY_MODE=self_host
mkdir -p secrets && openssl rand -base64 32 > secrets/master.key && chmod 0400 secrets/master.key
pnpm install && pnpm db:migrate && pnpm db:rls && pnpm isolation:selftest
pnpm build && pnpm start
```

No Stripe, no Redis, no KMS required (file KEK is accepted with a warning —
see THREAT_MODEL.md for what that trade-off means).
