"use client";
/**
 * Billing UI (hosted mode): save a card, buy a credit pack, configure
 * auto-recharge, sign out. Server endpoints do all authorization + validation;
 * this layer only collects card details via Stripe Elements (card data goes
 * straight to Stripe — it never touches our servers).
 */
import { useState } from "react";
import { loadStripe } from "@stripe/stripe-js";
import { Elements, PaymentElement, useStripe, useElements } from "@stripe/react-stripe-js";
import { authClient } from "@/auth/client";
import { PACKS_MICROS, formatUsd } from "@/billing/money";
import { postJson } from "./http";

const publishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY ?? "";
const stripePromise = publishableKey ? loadStripe(publishableKey) : null;

const box = { border: "1px solid #ccc", padding: 12, margin: "8px 0" } as const;

/**
 * Confirms a SetupIntent or PaymentIntent inside an <Elements> provider.
 * `redirect: "if_required"` keeps plain card flows on this page (we navigate
 * to the result banner ourselves); 3DS-style flows hard-redirect to the
 * return_url, where the dashboard reads `redirect_status` for the banner.
 */
function ConfirmForm({ kind, label }: { kind: "setup" | "payment"; label: string }) {
  const stripe = useStripe();
  const elements = useElements();
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div style={{ marginTop: 8 }}>
      <PaymentElement />
      <button
        disabled={!stripe || !elements || busy}
        style={{ marginTop: 8 }}
        onClick={async () => {
          if (!stripe || !elements) return;
          setBusy(true);
          setErr(null);
          const params = {
            elements,
            confirmParams: { return_url: `${window.location.origin}/dashboard` },
            redirect: "if_required" as const,
          };
          const res =
            kind === "setup" ? await stripe.confirmSetup(params) : await stripe.confirmPayment(params);
          if (res.error) {
            setErr(res.error.message ?? "failed");
            setBusy(false);
          } else {
            window.location.assign("/dashboard?redirect_status=succeeded");
          }
        }}
      >
        {label}
      </button>
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

/** One intent flow: action buttons fetch a clientSecret, then Elements confirms it. */
function IntentForm({
  title,
  blurb,
  kind,
  confirmLabel,
  actions,
}: {
  title: string;
  blurb: string;
  kind: "setup" | "payment";
  confirmLabel: string;
  actions: { label: string; getSecret: () => Promise<Record<string, unknown>> }[];
}) {
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (!stripePromise) return null;
  return (
    <div style={box}>
      <strong>{title}</strong>
      <p style={{ margin: "4px 0" }}>{blurb}</p>
      {!clientSecret ? (
        <div style={{ display: "flex", gap: 8 }}>
          {actions.map((a) => (
            <button
              key={a.label}
              onClick={async () => {
                setErr(null);
                setClientSecret(null);
                try {
                  const r = await a.getSecret();
                  setClientSecret((r.clientSecret as string) ?? null);
                } catch (e) {
                  setErr((e as Error).message);
                }
              }}
            >
              {a.label}
            </button>
          ))}
        </div>
      ) : (
        <Elements stripe={stripePromise} options={{ clientSecret }}>
          <ConfirmForm kind={kind} label={confirmLabel} />
        </Elements>
      )}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

export function SaveCardForm({ orgId }: { orgId: string }) {
  return (
    <IntentForm
      title="Card on file"
      blurb="Required for auto-recharge. Stored by Stripe, not by us."
      kind="setup"
      confirmLabel="Save card"
      actions={[
        { label: "Add / replace card", getSecret: () => postJson("/api/billing/setup-intent", { orgId }) },
      ]}
    />
  );
}

export function BuyPackForm({ orgId }: { orgId: string }) {
  return (
    <IntentForm
      title="Buy credits"
      blurb="$1 = 10,000 forwarded events. Credits never expire."
      kind="payment"
      confirmLabel="Pay"
      actions={PACKS_MICROS.map((p) => ({
        label: `${formatUsd(p)} pack`,
        getSecret: () => postJson("/api/billing/buy-pack", { orgId, packMicros: p.toString() }),
      }))}
    />
  );
}

export function AutoRechargeForm({
  orgId,
  enabled,
  thresholdUsd,
  targetUsd,
}: {
  orgId: string;
  enabled: boolean;
  thresholdUsd: number;
  targetUsd: number;
}) {
  const [on, setOn] = useState(enabled);
  const [threshold, setThreshold] = useState(String(thresholdUsd));
  const [target, setTarget] = useState(String(targetUsd));
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <div style={box}>
      <strong>Auto-recharge</strong>
      <p style={{ margin: "4px 0" }}>
        When the balance drops to the threshold, your saved card is charged up to the target. No
        cap is applied — you get an email on every charge.
      </p>
      <label style={{ display: "block", margin: "4px 0" }}>
        <input type="checkbox" checked={on} onChange={(e) => setOn(e.target.checked)} /> enabled
      </label>
      <label style={{ display: "block", margin: "4px 0" }}>
        at $&nbsp;
        <input value={threshold} onChange={(e) => setThreshold(e.target.value)} size={4} /> top up
        to $&nbsp;
        <input value={target} onChange={(e) => setTarget(e.target.value)} size={4} />
      </label>
      <button
        onClick={async () => {
          setMsg(null);
          setErr(null);
          try {
            const toMicros = (s: string) => String(Math.round(Number(s) * 1_000_000));
            await postJson("/api/billing/auto-recharge", {
              orgId,
              enabled: on,
              thresholdMicros: toMicros(threshold),
              targetMicros: toMicros(target),
            });
            setMsg("saved");
          } catch (e) {
            setErr((e as Error).message);
          }
        }}
      >
        Save
      </button>
      {msg && <span style={{ color: "green", marginLeft: 8 }}>{msg}</span>}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

export function SignOutButton() {
  return (
    <button
      onClick={async () => {
        await authClient.signOut();
        window.location.href = "/login";
      }}
    >
      Sign out
    </button>
  );
}
