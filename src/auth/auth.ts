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
  emailAndPassword: { enabled: true },
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
