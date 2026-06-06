"use client";
import { useState } from "react";

async function postJson(url: string, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((json as { error?: string }).error ?? `status ${res.status}`);
  return json;
}

export function CreateSourceForm({ orgId, projectId }: { orgId: string; projectId: string }) {
  const [out, setOut] = useState<{ drainUrl: string; bearer: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <div style={{ border: "1px solid #ccc", padding: 12, margin: "8px 0" }}>
      <strong>Add a Vercel source</strong>
      <div>
        <button
          onClick={async () => {
            setErr(null);
            try {
              setOut((await postJson("/api/sources", { orgId, projectId })) as typeof out);
            } catch (e) {
              setErr((e as Error).message);
            }
          }}
        >
          Create source
        </button>
      </div>
      {out && (
        <div style={{ background: "#fffbe6", padding: 8, marginTop: 8 }}>
          <p>
            <b>Drain URL:</b> <code>{out.drainUrl}</code>
          </p>
          <p>
            <b>Bearer (shown once — copy now):</b> <code>{out.bearer}</code>
          </p>
        </div>
      )}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </div>
  );
}

export function ConnectPostHogForm({ orgId }: { orgId: string }) {
  const [label, setLabel] = useState("PostHog");
  const [projectKey, setProjectKey] = useState("");
  const [host, setHost] = useState("https://us.i.posthog.com");
  const [siteUrl, setSiteUrl] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  return (
    <div style={{ border: "1px solid #ccc", padding: 12, margin: "8px 0" }}>
      <strong>Connect PostHog</strong>
      <input placeholder="label" value={label} onChange={(e) => setLabel(e.target.value)} />
      <input placeholder="project write key (phc_…)" value={projectKey} onChange={(e) => setProjectKey(e.target.value)} />
      <input placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} />
      <input placeholder="site url (https://www.you.com)" value={siteUrl} onChange={(e) => setSiteUrl(e.target.value)} />
      <button
        onClick={async () => {
          try {
            await postJson("/api/destinations/posthog", { orgId, label, projectKey, host, siteUrl });
            setMsg("connected");
          } catch (e) {
            setMsg((e as Error).message);
          }
        }}
      >
        Connect
      </button>
      {msg && <span> {msg}</span>}
    </div>
  );
}

export function ConnectGoogle({ orgId }: { orgId: string }) {
  return (
    <div style={{ border: "1px solid #ccc", padding: 12, margin: "8px 0" }}>
      <strong>Connect Google Sheets</strong>
      <div>
        <a href={`/api/oauth/google/start?orgId=${encodeURIComponent(orgId)}`}>Connect a Google Sheet →</a>
      </div>
    </div>
  );
}

export function CreateRouteForm({ orgId }: { orgId: string }) {
  const [sourceId, setSourceId] = useState("");
  const [destinationId, setDestinationId] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  return (
    <div style={{ border: "1px solid #ccc", padding: 12, margin: "8px 0" }}>
      <strong>Wire source → destination</strong>
      <input placeholder="source id" value={sourceId} onChange={(e) => setSourceId(e.target.value)} />
      <input placeholder="destination id" value={destinationId} onChange={(e) => setDestinationId(e.target.value)} />
      <button
        onClick={async () => {
          try {
            await postJson("/api/routes", { orgId, sourceId, destinationId });
            setMsg("routed");
          } catch (e) {
            setMsg((e as Error).message);
          }
        }}
      >
        Create route
      </button>
      {msg && <span> {msg}</span>}
    </div>
  );
}
