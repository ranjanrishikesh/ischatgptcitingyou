import { redirect } from "next/navigation";
import { getSessionUser, defaultOrg } from "@/auth/session";
import { listProjects } from "@/services/projects";
import { listSources } from "@/services/sources";
import { listDestinations } from "@/services/destinations";
import { listRoutes } from "@/services/routes";
import { CreateSourceForm, ConnectPostHogForm, ConnectGoogle, CreateRouteForm } from "./forms";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export default async function Dashboard() {
  const user = await getSessionUser();
  if (!user) redirect("/login");
  const orgId = await defaultOrg(user.id);
  if (!orgId) return <main style={{ padding: 24 }}>No organization provisioned.</main>;

  const [projects, sources, dests, routes] = await Promise.all([
    listProjects(orgId),
    listSources(orgId),
    listDestinations(orgId),
    listRoutes(orgId),
  ]);
  const projectId = projects[0]?.id ?? "";

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 820, margin: "2rem auto", padding: "0 1rem" }}>
      <h1>Dashboard</h1>
      <p>
        Signed in as {user.email} · org <code>{orgId}</code>
      </p>

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
