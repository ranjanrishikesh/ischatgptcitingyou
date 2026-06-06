/**
 * Minimal transactional email. Uses Resend if configured, else logs (no-op) so
 * self-host / dev don't require an email provider. All sends are best-effort and
 * never throw — a failed notification must not break billing.
 */
import { safeFetch } from "../egress/safeFetch";

export interface EmailInput {
  to: string;
  subject: string;
  text: string;
}

export async function sendEmail(input: EmailInput): Promise<void> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM ?? "noreply@ischatgptcitingyou.com";
  if (!key) {
    console.log("[email:noop]", { to: input.to, subject: input.subject });
    return;
  }
  try {
    await safeFetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({ from, to: input.to, subject: input.subject, text: input.text }),
    });
  } catch (e) {
    console.error("email send failed", { to: input.to, subject: input.subject, err: (e as Error).message });
  }
}
