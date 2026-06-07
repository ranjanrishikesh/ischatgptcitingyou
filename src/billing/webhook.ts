/**
 * Stripe webhook processing. Credits are applied HERE (not at charge time) so a
 * charge and its credit can't diverge.
 *
 * Idempotency relies SOLELY on the ledger's per-PI unique key
 * (`stripe_pi:<id>`): a duplicate/redelivered event re-runs appendLedger, which
 * no-ops via ON CONFLICT — so it can't double-credit, and (crucially) a crash
 * before the credit commits leaves NOTHING marked, so Stripe's retry safely
 * re-credits. (An earlier "processed event" marker was removed: committing it in
 * a separate transaction before the credit could permanently drop a real credit
 * if the process died in between.)
 */
import type Stripe from "stripe";
import { appendLedger } from "./ledger";
import { setHotBalance, clearRechargePending } from "./balance";
import { setDefaultPaymentMethod } from "./stripe";
import { formatUsd } from "./money";
import { sendEmail } from "../email/send";
import { getOrgOwnerEmail } from "../services/orgOwner";

export async function handleStripeEvent(event: Stripe.Event): Promise<void> {
  if (event.type === "payment_intent.succeeded") {
    await onPaymentSucceeded(event.data.object as Stripe.PaymentIntent);
  } else if (event.type === "setup_intent.succeeded") {
    await onSetupSucceeded(event.data.object as Stripe.SetupIntent);
  }
}

async function onPaymentSucceeded(pi: Stripe.PaymentIntent): Promise<void> {
  const orgId = pi.metadata?.orgId;
  const kind = pi.metadata?.kind;
  const micros = pi.metadata?.micros;
  if (!orgId || (kind !== "purchase" && kind !== "recharge") || !micros) return;

  const amount = BigInt(micros);
  const res = await appendLedger(orgId, {
    kind,
    amountMicros: amount,
    idempotencyKey: `stripe_pi:${pi.id}`,
    stripePaymentIntentId: pi.id,
  });

  // Release the recharge marker ONLY AFTER the credit is durably committed
  // (appendLedger returning means its tx committed). Clearing it before the
  // commit would let a concurrent reconcile see "no marker + un-credited
  // balance" and start a SECOND recharge — a double charge.
  if (kind === "recharge") await clearRechargePending(orgId);

  if (!res.applied) return; // duplicate delivery — already credited (and emailed)
  await setHotBalance(orgId, res.balanceMicros);
  const email = await getOrgOwnerEmail(orgId);
  if (email) {
    const verb = kind === "recharge" ? "auto-recharged" : "added";
    await sendEmail({
      to: email,
      subject: `Payment received — balance ${formatUsd(res.balanceMicros)}`,
      text: `We ${verb} ${formatUsd(amount)} to your ischatgptcitingyou balance. New balance: ${formatUsd(res.balanceMicros)}.`,
    });
  }
}

async function onSetupSucceeded(si: Stripe.SetupIntent): Promise<void> {
  const orgId = si.metadata?.orgId;
  const pm = typeof si.payment_method === "string" ? si.payment_method : si.payment_method?.id;
  if (!orgId || !pm) return;
  await setDefaultPaymentMethod(orgId, pm); // idempotent — safe to repeat
}
