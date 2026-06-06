/**
 * Stripe integration (hosted only). Handles the customer, saved-card setup,
 * one-time pack purchases, and off-session auto-recharge. Credits are NEVER
 * applied here — only the webhook (on payment_intent.succeeded) writes the
 * ledger, so a charge and its credit can't diverge.
 */
import Stripe from "stripe";
import { and, eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { stripeCustomer } from "../db/schema";
import { microsToStripeCents, PACKS_MICROS } from "./money";

let _stripe: Stripe | null = null;
export function stripe(): Stripe {
  if (!_stripe) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error("STRIPE_SECRET_KEY not set");
    _stripe = new Stripe(key);
  }
  return _stripe;
}

interface CustomerRow {
  stripeCustomerId: string;
  defaultPaymentMethodId: string | null;
}

async function customerRow(orgId: string): Promise<CustomerRow | null> {
  const rows = await withOrg(orgId, (db) =>
    db
      .select({
        stripeCustomerId: stripeCustomer.stripeCustomerId,
        defaultPaymentMethodId: stripeCustomer.defaultPaymentMethodId,
      })
      .from(stripeCustomer)
      .where(eq(stripeCustomer.orgId, orgId)),
  );
  return rows[0] ?? null;
}

export async function getOrCreateCustomer(orgId: string): Promise<string> {
  const existing = await customerRow(orgId);
  if (existing) return existing.stripeCustomerId;
  // Idempotency key collapses concurrent first-time creates to one Stripe customer.
  const cust = await stripe().customers.create(
    { metadata: { orgId } },
    { idempotencyKey: `customer:${orgId}` },
  );
  await withOrg(orgId, (db) =>
    db.insert(stripeCustomer).values({ orgId, stripeCustomerId: cust.id }).onConflictDoNothing(),
  );
  // Re-read in case a concurrent create won the insert (avoids orphan use).
  return (await customerRow(orgId))?.stripeCustomerId ?? cust.id;
}

/** SetupIntent to save a card for off-session use. Returns the client secret. */
export async function createSetupIntent(orgId: string): Promise<string> {
  const customer = await getOrCreateCustomer(orgId);
  const si = await stripe().setupIntents.create({
    customer,
    usage: "off_session",
    metadata: { orgId },
  });
  if (!si.client_secret) throw new Error("no setup intent client_secret");
  return si.client_secret;
}

/** PaymentIntent for a one-time credit pack ($50/$100). Returns the client secret. */
export async function createPackPaymentIntent(orgId: string, packMicros: bigint): Promise<string> {
  if (!PACKS_MICROS.some((p) => p === packMicros)) throw new Error("invalid pack");
  const customer = await getOrCreateCustomer(orgId);
  const pi = await stripe().paymentIntents.create({
    amount: microsToStripeCents(packMicros),
    currency: "usd",
    customer,
    setup_future_usage: "off_session",
    metadata: { orgId, kind: "purchase", micros: packMicros.toString() },
  });
  if (!pi.client_secret) throw new Error("no payment intent client_secret");
  return pi.client_secret;
}

/** Persist the saved card as the customer's default payment method. */
export async function setDefaultPaymentMethod(orgId: string, paymentMethodId: string): Promise<void> {
  const customer = await getOrCreateCustomer(orgId);
  await stripe().customers.update(customer, {
    invoice_settings: { default_payment_method: paymentMethodId },
  });
  await withOrg(orgId, (db) =>
    db
      .update(stripeCustomer)
      .set({ defaultPaymentMethodId: paymentMethodId })
      .where(eq(stripeCustomer.orgId, orgId)),
  );
}

export class NoCardError extends Error {}

/**
 * Charge the saved card off-session (auto-recharge). The idempotencyKey makes a
 * retry safe. Throws NoCardError if no card is saved, or a StripeCardError on
 * decline / authentication_required (caller emails the customer).
 */
export async function chargeOffSession(
  orgId: string,
  micros: bigint,
  idempotencyKey: string,
  kind: "recharge",
): Promise<Stripe.PaymentIntent> {
  const row = await customerRow(orgId);
  if (!row?.defaultPaymentMethodId) throw new NoCardError("no saved card");
  return stripe().paymentIntents.create(
    {
      amount: microsToStripeCents(micros),
      currency: "usd",
      customer: row.stripeCustomerId,
      payment_method: row.defaultPaymentMethodId,
      off_session: true,
      confirm: true,
      metadata: { orgId, kind, micros: micros.toString() },
    },
    { idempotencyKey },
  );
}
