import type { Config } from "drizzle-kit";

// Migrations run as the OWNER role. The runtime app role is a separate,
// non-owner, no-BYPASSRLS role (see DATABASE_URL vs DATABASE_OWNER_URL).
export default {
  schema: "./src/db/schema.ts",
  out: "./src/db/migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_OWNER_URL ?? process.env.DATABASE_URL ?? "",
  },
} satisfies Config;
