/**
 * Database schema (Drizzle / Postgres).
 *
 * Tenancy: the hard boundary is `organization`. Every tenant-scoped table carries
 * `orgId` and is protected by FORCE ROW LEVEL SECURITY keyed on a per-transaction
 * GUC (`app.current_org`). See applyRls.ts and client.ts. A missing GUC yields
 * ZERO rows (fail closed), never all rows.
 *
 * Secrets: we store NO customer traffic. The only sensitive data at rest is a
 * destination credential, held encrypted (envelope) in `destination.secretCiphertext`.
 * Money lives in an append-only `ledgerEntry` table; `balance` is a materialized
 * cache updated in the same transaction as each ledger append.
 */
import {
  pgTable,
  uuid,
  text,
  timestamp,
  jsonb,
  bigint,
  boolean,
  customType,
  pgEnum,
  unique,
  index,
} from "drizzle-orm/pg-core";

/** Postgres bytea <-> Node Buffer. */
export const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

export const destinationKind = pgEnum("destination_kind", [
  "posthog",
  "mixpanel",
  "amplitude",
  "google_sheets",
]);

export const sourceKind = pgEnum("source_kind", ["vercel"]);

export const memberRole = pgEnum("member_role", ["owner", "admin", "member", "viewer"]);

export const ledgerKind = pgEnum("ledger_kind", [
  "free_grant",
  "purchase",
  "recharge",
  "usage",
  "refund",
  "adjustment",
]);

// --- Identity --------------------------------------------------------------
// `account` is global to a person (auth). Not org-scoped. Better Auth manages
// its own session/credential tables separately; this is the app-side profile.
export const account = pgTable("account", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull().unique(),
  name: text("name"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// The tenant boundary. Holds the wrapped per-tenant DEK.
export const organization = pgTable("organization", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  // Wrapped per-tenant DEK + which KEK wrapped it (for rotation/audit).
  wrappedDek: bytea("wrapped_dek").notNull(),
  kekKeyId: text("kek_key_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const membership = pgTable(
  "membership",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    accountId: uuid("account_id")
      .notNull()
      .references(() => account.id, { onDelete: "cascade" }),
    role: memberRole("role").notNull().default("member"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    uniqAcctOrg: unique("membership_acct_org").on(t.accountId, t.orgId),
    byOrg: index("membership_org_idx").on(t.orgId),
  }),
);

// --- Pipeline config -------------------------------------------------------
export const project = pgTable(
  "project",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({ byOrg: index("project_org_idx").on(t.orgId) }),
);

export const source = pgTable(
  "source",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => project.id, { onDelete: "cascade" }),
    kind: sourceKind("kind").notNull().default("vercel"),
    // Public, opaque routing token (the "ind_live_..." in the drain URL). Not a
    // secret on its own — it is a username. Indexed for O(1) lookup.
    ingestIdPublic: text("ingest_id_public").notNull().unique(),
    // HMAC of the per-source bearer secret. The plaintext secret is shown ONCE
    // at creation and never stored.
    bearerHash: text("bearer_hash").notNull(),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({ byOrg: index("source_org_idx").on(t.orgId) }),
);

export const destination = pgTable(
  "destination",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    kind: destinationKind("kind").notNull(),
    label: text("label").notNull(),
    // Encrypted credential (envelope). NULL until configured.
    secretCiphertext: bytea("secret_ciphertext"),
    secretType: text("secret_type"), // AAD binding, e.g. "posthog_project_key"
    // Non-secret config: posthog host, sheet id, etc.
    config: jsonb("config").notNull().default({}),
    // Display-only confirmation, gated to admins in the API layer.
    last4: text("last4"),
    lastRotatedAt: timestamp("last_rotated_at", { withTimezone: true }),
    status: text("status").notNull().default("pending"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({ byOrg: index("destination_org_idx").on(t.orgId) }),
);

// Route = the join edge (which source feeds which destination). Fan-out is many
// destinations per source. The triple-equality invariant (source.org ==
// destination.org == session.org) is enforced in app + a DB trigger backstop.
export const route = pgTable(
  "route",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    sourceId: uuid("source_id")
      .notNull()
      .references(() => source.id, { onDelete: "cascade" }),
    destinationId: uuid("destination_id")
      .notNull()
      .references(() => destination.id, { onDelete: "cascade" }),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    byOrg: index("route_org_idx").on(t.orgId),
    uniqEdge: unique("route_src_dst").on(t.sourceId, t.destinationId),
  }),
);

// --- Billing ---------------------------------------------------------------
// Append-only. No UPDATE/DELETE (enforced by RLS having no such policies).
export const ledgerEntry = pgTable(
  "ledger_entry",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    kind: ledgerKind("kind").notNull(),
    // Signed micro-dollars: + credits (grant/purchase/recharge/refund), - usage.
    amountMicros: bigint("amount_micros", { mode: "bigint" }).notNull(),
    stripePaymentIntentId: text("stripe_payment_intent_id"),
    // Idempotency: a recharge / webhook can be retried without double-applying.
    idempotencyKey: text("idempotency_key"),
    meta: jsonb("meta").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    byOrg: index("ledger_org_idx").on(t.orgId),
    // Per-ORG idempotency. A single-column unique would be GLOBAL (uniqueness is
    // enforced beneath RLS), letting one org's key collision silently block
    // another org's credit. NULL keys stay distinct, so usage debits are free
    // to repeat. (orgId, idempotencyKey) scopes idempotency to the tenant.
    uniqIdem: unique("ledger_idempotency").on(t.orgId, t.idempotencyKey),
  }),
);

// Materialized balance (= sum of ledger), updated in the same tx as each append.
export const balance = pgTable("balance", {
  orgId: uuid("org_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  balanceMicros: bigint("balance_micros", { mode: "bigint" }).notNull().default(0n),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const stripeCustomer = pgTable("stripe_customer", {
  orgId: uuid("org_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  stripeCustomerId: text("stripe_customer_id").notNull(),
  defaultPaymentMethodId: text("default_payment_method_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const autoRechargeConfig = pgTable("auto_recharge_config", {
  orgId: uuid("org_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  enabled: boolean("enabled").notNull().default(false),
  // Defaults match the locked policy: trigger at $5, top up to $20.
  thresholdMicros: bigint("threshold_micros", { mode: "bigint" }).notNull().default(5_000_000n),
  targetMicros: bigint("target_micros", { mode: "bigint" }).notNull().default(20_000_000n),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// Stripe webhook idempotency — every event processed at most once.
export const processedStripeEvent = pgTable("processed_stripe_event", {
  eventId: text("event_id").primaryKey(),
  processedAt: timestamp("processed_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Tenant-scoped tables that MUST have FORCE RLS applied (keyed on org_id). */
export const TENANT_TABLES = [
  "organization",
  "membership",
  "project",
  "source",
  "destination",
  "route",
  "ledger_entry",
  "balance",
  "stripe_customer",
  "auto_recharge_config",
] as const;
