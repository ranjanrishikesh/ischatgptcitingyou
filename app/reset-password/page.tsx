"use client";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { authClient } from "@/auth/client";

/**
 * Two modes on one page:
 *  - no ?token: ask for the account email, send the reset link
 *  - ?token=…: set the new password (link target from the email)
 * The request form always reports success — whether or not the email exists —
 * so this page is not an account-enumeration oracle.
 */
function ResetPasswordInner() {
  const token = useSearchParams().get("token");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function requestLink() {
    setBusy(true);
    setErr(null);
    try {
      await authClient.requestPasswordReset({
        email,
        redirectTo: "/reset-password",
      });
      setMsg("If that address has an account, a reset link is on its way.");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function setNewPassword() {
    setBusy(true);
    setErr(null);
    try {
      const res = await authClient.resetPassword({ newPassword: password, token: token! });
      if ((res as { error?: { message?: string } }).error) {
        setErr(
          (res as { error?: { message?: string } }).error?.message ??
            "Reset failed — the link may have expired. Request a new one.",
        );
      } else {
        window.location.href = "/login";
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 360, margin: "5rem auto", padding: "0 1rem" }}>
      <h1>Reset password</h1>
      {!token ? (
        <>
          <p>Enter your account email and we&apos;ll send a reset link.</p>
          <input
            placeholder="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ display: "block", width: "100%", margin: "0.5rem 0", padding: 8 }}
          />
          <button disabled={busy || !email} onClick={requestLink}>
            Send reset link
          </button>
        </>
      ) : (
        <>
          <p>Choose a new password.</p>
          <input
            placeholder="new password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ display: "block", width: "100%", margin: "0.5rem 0", padding: 8 }}
          />
          <button disabled={busy || password.length < 8} onClick={setNewPassword}>
            Set new password
          </button>
        </>
      )}
      {msg && <p style={{ color: "green" }}>{msg}</p>}
      {err && <p style={{ color: "crimson" }}>{err}</p>}
      <p>
        <a href="/login">Back to sign in</a>
      </p>
    </main>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordInner />
    </Suspense>
  );
}
