/** Shared fetch helper for dashboard client forms. */
export async function postJson(url: string, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json: unknown = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((json as { error?: string }).error ?? `status ${res.status}`);
  // Callers cast to their endpoint's response shape (same contract as before).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return json as any;
}
