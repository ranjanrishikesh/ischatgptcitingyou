/** Stripe webhook. Verifies the signature over the RAW body, then dispatches. */
import { stripe } from "@/billing/stripe";
import { handleStripeEvent } from "@/billing/webhook";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  const sig = req.headers.get("stripe-signature");
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const body = await req.text(); // raw body required for signature verification

  let event;
  try {
    event = stripe().webhooks.constructEvent(body, sig ?? "", secret ?? "");
  } catch {
    return new Response("bad signature", { status: 400 });
  }

  try {
    await handleStripeEvent(event);
  } catch (e) {
    console.error("webhook handler failed", { type: event.type, err: (e as Error).message });
    return new Response("handler error", { status: 500 }); // Stripe will retry
  }
  return new Response("ok", { status: 200 });
}
