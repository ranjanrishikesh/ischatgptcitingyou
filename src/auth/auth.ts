/**
 * Better Auth configuration. Email+password sign-in, opaque server-side sessions.
 * On user creation we provision their org (DEK + owner membership + balance +
 * $1 grant). Better Auth talks to Postgres as the runtime role; the auth tables
 * are not tenant-scoped (granted directly in applyRls).
 */
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "../db/schema";
import { provisionOrg } from "../services/provisioning";
import { sendEmail } from "../email/send";

const client = postgres(process.env.DATABASE_URL ?? "", { prepare: false });
const db = drizzle(client, { schema });

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.authAccount,
      verification: schema.verification,
    },
  }),
  secret: process.env.BETTER_AUTH_SECRET,
  baseURL: process.env.BETTER_AUTH_URL,
  emailAndPassword: {
    enabled: true,
    // Without this, better-auth rejects /forget-password outright and a
    // customer who loses their password is unrecoverable short of DB surgery.
    // The link delivers only if RESEND_API_KEY is set (posture enforces it in
    // hosted mode); the message never includes the raw token outside the URL.
    sendResetPassword: async ({ user, url }) => {
      await sendEmail({
        to: user.email,
        subject: "Reset your ischatgptcitingyou password",
        text:
          `Someone (hopefully you) asked to reset the password for ${user.email}.\n\n` +
          `Reset it here (link expires in 1 hour):\n${url}\n\n` +
          `If this wasn't you, ignore this email — your password is unchanged.`,
      });
    },
  },
  databaseHooks: {
    user: {
      create: {
        after: async (created: { id: string; email: string }) => {
          await provisionOrg(created.id, `${created.email}'s workspace`);
        },
      },
    },
  },
});
