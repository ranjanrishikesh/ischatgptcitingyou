/**
 * Auto-recharge. When an org's balance is at/below its threshold, charge the
 * saved card up to the target ($5 -> $20 by default). The founder chose NO
 * recharge cap, so this can repeat; we mitigate with an email on every charge
 * (sent by the webhook on success) and a spike alert here, NOT a hard ceiling.
 *
 * Concurrency-safe via singleFlightRecharge; idempotent via the Stripe key and
 * the post-credit balance re-check (which naturally stops repeat charges once
 * the balance is back above threshold).
 */
import { getBalanceMicros } from "./ledger";
import { rechargeChargeMicros } from "./money";
import { getAutoRechargeConfig } from "./autoRecharge";
import {
  singleFlightRecharge,
  bumpRechargeCount,
  setRechargePending,
  clearRechargePending,
} from "./balance";
import { chargeOffSession, NoCardError } from "./stripe";
import { sendEmail } from "../email/send";
import { getOrgOwnerEmail } from "../services/orgOwner";

export const SPIKE_THRESHOLD = 5; // auto-recharges/hour before alerting
// Marker lifetime: long enough to cover webhook delivery, short enough to
// self-heal if a webhook is permanently lost.
const RECHARGE_PENDING_TTL_SEC = 3600;

export async function maybeAutoRecharge(orgId: string, balanceMicros: bigint): Promise<void> {
  const cfg = await getAutoRechargeConfig(orgId);
  if (!cfg.enabled) return;
  if (rechargeChargeMicros(balanceMicros, cfg.thresholdMicros, cfg.targetMicros) <= 0n) return;

  await singleFlightRecharge(orgId, 30_000, async () => {
    // A prior charge whose credit hasn't landed yet holds the pending marker —
    // don't charge again until the webhook clears it. setRechargePending is NX,
    // so claiming it here both checks and reserves atomically.
    if (!(await setRechargePending(orgId, RECHARGE_PENDING_TTL_SEC))) return;

    // Re-check against the authoritative balance inside the lock.
    const fresh = await getBalanceMicros(orgId);
    const need = rechargeChargeMicros(fresh, cfg.thresholdMicros, cfg.targetMicros);
    if (need <= 0n) {
      await clearRechargePending(orgId);
      return;
    }

    // Idempotency key NOT keyed on the (moving) amount — one charge per org per
    // hour bucket, so a retry can't create a second PaymentIntent.
    const hour = Math.floor(Date.now() / 3_600_000);
    const idem = `recharge:${orgId}:${hour}`;
    try {
      await chargeOffSession(orgId, need, idem, "recharge");
      // The success "we charged $X" email + the pending-marker CLEAR happen in
      // the webhook on payment_intent.succeeded (which also credits the ledger).
      const count = await bumpRechargeCount(orgId);
      if (count > SPIKE_THRESHOLD) {
        const email = await getOrgOwnerEmail(orgId);
        if (email) {
          await sendEmail({
            to: email,
            subject: "Unusual auto-recharge activity on ischatgptcitingyou",
            text:
              `Your account auto-recharged ${count} times in the past hour. If this is unexpected, a ` +
              `bot may be hammering your site — review your traffic. (No cap is applied to auto-recharge.)`,
          });
        }
      }
    } catch (e) {
      // Charge failed — release the marker so a later tick can retry.
      await clearRechargePending(orgId);
      const email = await getOrgOwnerEmail(orgId);
      if (email) {
        const reason =
          e instanceof NoCardError
            ? "no card is saved"
            : "your card was declined or needs authentication";
        await sendEmail({
          to: email,
          subject: "Auto-recharge failed on ischatgptcitingyou",
          text: `We couldn't top up your balance (${reason}). Forwarding will pause when credits run out. Please update your card in the dashboard.`,
        });
      }
      console.error("auto-recharge failed", { orgId, err: (e as Error).message });
    }
  });
}
