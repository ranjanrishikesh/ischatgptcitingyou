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

const publishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY ?? "";
const stripePromise = publishableKey ? loadStripe(publishableKey) : null;

async function postJson(url: string, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((json as { error?: string }).error ?? `status ${res.status}`);
  return json as { clientSecret?: string; ok?: boolean };
}

const box = { border: "1px solid #ccc", padding: 12, margin: "8px 0" } as const;

/** Confirms a SetupIntent or PaymentIntent inside an <Elements> provider. */
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
          };
          const res =
            kind === "setup" ? await stripe.confirmSetup(params) : await stripe.confirmPayment(params);
          if (res.error) setErr(res.error.message ?? "failed");
          setBusy(false);
        }}
      >
        {label}
      </button>
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

export function SaveCardForm({ orgId }: { orgId: string }) {
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (!stripePromise) return null;
  return (
    <div style={box}>
      <strong>Card on file</strong>
      <p style={{ margin: "4px 0" }}>Required for auto-recharge. Stored by Stripe, not by us.</p>
      {!clientSecret ? (
        <button
          onClick={async () => {
            setErr(null);
            try {
              const r = await postJson("/api/billing/setup-intent", { orgId });
              setClientSecret(r.clientSecret ?? null);
            } catch (e) {
              setErr((e as Error).message);
            }
          }}
        >
          Add / replace card
        </button>
      ) : (
        <Elements stripe={stripePromise} options={{ clientSecret }}>
          <ConfirmForm kind="setup" label="Save card" />
        </Elements>
      )}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

export function BuyPackForm({ orgId }: { orgId: string }) {
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (!stripePromise) return null;
  const buy = async (packMicros: string) => {
    setErr(null);
    setClientSecret(null);
    try {
      const r = await postJson("/api/billing/buy-pack", { orgId, packMicros });
      setClientSecret(r.clientSecret ?? null);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <div style={box}>
      <strong>Buy credits</strong>
      <p style={{ margin: "4px 0" }}>$1 = 10,000 forwarded events. Credits never expire.</p>
      {!clientSecret ? (
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => buy("50000000")}>$50 pack</button>
          <button onClick={() => buy("100000000")}>$100 pack</button>
        </div>
      ) : (
        <Elements stripe={stripePromise} options={{ clientSecret }}>
          <ConfirmForm kind="payment" label="Pay" />
        </Elements>
      )}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
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
