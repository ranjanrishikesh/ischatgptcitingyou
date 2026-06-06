"use client";
import { useState } from "react";
import { authClient } from "@/auth/client";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(mode: "in" | "up") {
    setBusy(true);
    setErr(null);
    try {
      const res =
        mode === "in"
          ? await authClient.signIn.email({ email, password })
          : await authClient.signUp.email({ email, password, name: email });
      if ((res as { error?: { message?: string } }).error) {
        setErr((res as { error?: { message?: string } }).error?.message ?? "failed");
      } else {
        window.location.href = "/dashboard";
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 360, margin: "5rem auto", padding: "0 1rem" }}>
      <h1>is ChatGPT citing you?</h1>
      <p>Sign in or create an account.</p>
      <input
        placeholder="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        style={{ display: "block", width: "100%", margin: "0.5rem 0", padding: 8 }}
      />
      <input
        placeholder="password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        style={{ display: "block", width: "100%", margin: "0.5rem 0", padding: 8 }}
      />
      <div style={{ display: "flex", gap: 8 }}>
        <button disabled={busy} onClick={() => submit("in")}>
          Sign in
        </button>
        <button disabled={busy} onClick={() => submit("up")}>
          Create account
        </button>
      </div>
      {err && <p style={{ color: "crimson" }}>{err}</p>}
    </main>
  );
}
