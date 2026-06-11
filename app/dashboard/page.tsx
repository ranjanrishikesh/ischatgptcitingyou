import { redirect } from "next/navigation";
import { getSessionUser, defaultOrg } from "@/auth/session";
import { listProjects } from "@/services/projects";
import { listSources } from "@/services/sources";
import { listDestinations } from "@/services/destinations";
import { listRoutes } from "@/services/routes";
import { isHosted } from "@/config/deployMode";
import { getBalanceMicros } from "@/billing/ledger";
import { getAutoRechargeConfig } from "@/billing/autoRecharge";
import { formatUsd, microsToEvents, MICRO_PER_DOLLAR } from "@/billing/money";
import { CreateSourceForm, ConnectPostHogForm, ConnectGoogle, CreateRouteForm } from "./forms";
import { SaveCardForm, BuyPackForm, AutoRechargeForm, SignOutButton } from "./billing";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export default async function Dashboard() {
  const user = await getSessionUser();
  if (!user) redirect("/login");
  const orgId = await defaultOrg(user.id);
  if (!orgId) return <main style={{ padding: 24 }}>No organization provisioned.</main>;

  const hosted = isHosted();
  const [projects, sources, dests, routes, balance, recharge] = await Promise.all([
    listProjects(orgId),
    listSources(orgId),
    listDestinations(orgId),
    listRoutes(orgId),
    hosted ? getBalanceMicros(orgId) : Promise.resolve(0n),
    hosted ? getAutoRechargeConfig(orgId) : Promise.resolve(null),
  ]);
  const projectId = projects[0]?.id ?? "";

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 820, margin: "2rem auto", padding: "0 1rem" }}>
      <h1>Dashboard</h1>
      <p>
        Signed in as {user.email} · org <code>{orgId}</code> · <SignOutButton />
      </p>

      {hosted && (
        <>
          <h2>Billing</h2>
          <p>
            Balance: <b>{formatUsd(balance)}</b> (≈ {microsToEvents(balance).toLocaleString()}{" "}
            events left)
          </p>
          <SaveCardForm orgId={orgId} />
          <BuyPackForm orgId={orgId} />
          <AutoRechargeForm
            orgId={orgId}
            enabled={recharge?.enabled ?? false}
            thresholdUsd={Number((recharge?.thresholdMicros ?? 5_000_000n) / MICRO_PER_DOLLAR)}
            targetUsd={Number((recharge?.targetMicros ?? 20_000_000n) / MICRO_PER_DOLLAR)}
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
