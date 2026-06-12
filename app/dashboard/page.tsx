import { redirect } from "next/navigation";
import { getSessionUser, defaultOrg } from "@/auth/session";
import { listProjects } from "@/services/projects";
import { listSources } from "@/services/sources";
import { listDestinations } from "@/services/destinations";
import { listRoutes } from "@/services/routes";
import { isHosted } from "@/config/deployMode";
import { getBillingSummary } from "@/billing/autoRecharge";
import {
  formatUsd,
  microsToEvents,
  MICRO_PER_DOLLAR,
  AUTO_RECHARGE_THRESHOLD_MICROS,
  AUTO_RECHARGE_TARGET_MICROS,
} from "@/billing/money";
import { CreateSourceForm, ConnectPostHogForm, ConnectGoogle, CreateRouteForm } from "./forms";
import { SaveCardForm, BuyPackForm, AutoRechargeForm, SignOutButton } from "./billing";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Stripe sends the browser back here after a redirect-based confirmation;
// `redirect_status` drives a one-shot result banner (no card/intent data).
const BANNERS: Record<string, { color: string; text: string }> = {
  succeeded: {
    color: "green",
    text: "Payment received — your balance updates within a minute. Refresh to see it.",
  },
  processing: { color: "#666", text: "Payment processing — your balance updates once it completes." },
  failed: { color: "crimson", text: "Payment failed or was canceled — you have not been charged." },
};

export default async function Dashboard({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const user = await getSessionUser();
  if (!user) redirect("/login");
  const orgId = await defaultOrg(user.id);
  if (!orgId) return <main style={{ padding: 24 }}>No organization provisioned.</main>;

  const sp = await searchParams;
  const banner = typeof sp.redirect_status === "string" ? BANNERS[sp.redirect_status] : undefined;

  const hosted = isHosted();
  const [projects, sources, dests, routes, billing] = await Promise.all([
    listProjects(orgId),
    listSources(orgId),
    listDestinations(orgId),
    listRoutes(orgId),
    hosted ? getBillingSummary(orgId) : Promise.resolve(null),
  ]);
  const projectId = projects[0]?.id ?? "";

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 820, margin: "2rem auto", padding: "0 1rem" }}>
      <h1>Dashboard</h1>
      <p>
        Signed in as {user.email} · org <code>{orgId}</code> · <SignOutButton />
      </p>

      {banner && <p style={{ color: banner.color, fontWeight: 600 }}>{banner.text}</p>}

      {hosted && billing && (
        <>
          <h2>Billing</h2>
          <p>
            Balance: <b>{formatUsd(billing.balanceMicros)}</b> (≈{" "}
            {microsToEvents(billing.balanceMicros).toLocaleString()} events left)
          </p>
          <SaveCardForm orgId={orgId} />
          <BuyPackForm orgId={orgId} />
          <AutoRechargeForm
            orgId={orgId}
            enabled={billing.recharge.enabled}
            thresholdUsd={Number(
              (billing.recharge.thresholdMicros ?? AUTO_RECHARGE_THRESHOLD_MICROS) / MICRO_PER_DOLLAR,
            )}
            targetUsd={Number(
              (billing.recharge.targetMicros ?? AUTO_RECHARGE_TARGET_MICROS) / MICRO_PER_DOLLAR,
            )}
          />
        </>
      )}

      <h2>Sources</h2>
      <ul>
        {sources.map((s) => (
          <li key={s.id}>
            <code>{s.id}</code> — {s.status} — <code>{s.ingestIdPublic}</code>
          </li>
        ))}
      </ul>
      <CreateSourceForm orgId={orgId} projectId={projectId} />

      <h2>Destinations</h2>
      <ul>
        {dests.map((d) => (
          <li key={d.id}>
            <code>{d.id}</code> — {d.kind} — {d.label} — {d.status}
            {d.last4 ? ` — …${d.last4}` : ""}
          </li>
        ))}
      </ul>
      <ConnectPostHogForm orgId={orgId} />
      <ConnectGoogle orgId={orgId} />

      <h2>Routes</h2>
      <ul>
        {routes.map((r) => (
          <li key={r.id}>
            <code>{r.sourceId}</code> → <code>{r.destinationId}</code> {r.enabled ? "" : "(disabled)"}
          </li>
        ))}
      </ul>
      <CreateRouteForm orgId={orgId} />
    </main>
  );
}
