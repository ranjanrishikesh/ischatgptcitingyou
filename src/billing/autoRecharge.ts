/**
 * Auto-recharge configuration. Defaults match the locked policy: trigger at $5,
 * top up to $20. Disabled until the customer opts in (and has saved a card).
 */
import { eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { autoRechargeConfig } from "../db/schema";
import { AUTO_RECHARGE_THRESHOLD_MICROS, AUTO_RECHARGE_TARGET_MICROS, dollars } from "./money";

// Bounds so a typo or hostile member can't configure a card-draining or
// constantly-firing recharge.
const MIN_GAP = dollars(1); // target must lift the balance at least $1 above threshold
const MAX_THRESHOLD = dollars(100);
const MAX_TARGET = dollars(500);

export function validateBounds(thresholdMicros: bigint, targetMicros: bigint): void {
  if (thresholdMicros < 0n) throw new Error("threshold must be >= 0");
  if (thresholdMicros > MAX_THRESHOLD) throw new Error("threshold too high");
  if (targetMicros > MAX_TARGET) throw new Error("target too high");
  if (targetMicros <= thresholdMicros) throw new Error("target must exceed threshold");
  if (targetMicros - thresholdMicros < MIN_GAP) throw new Error("target/threshold gap too small");
}

export interface AutoRechargeConfig {
  enabled: boolean;
  thresholdMicros: bigint;
  targetMicros: bigint;
}

export async function getAutoRechargeConfig(orgId: string): Promise<AutoRechargeConfig> {
  const rows = await withOrg(orgId, (db) =>
    db
      .select({
        enabled: autoRechargeConfig.enabled,
        thresholdMicros: autoRechargeConfig.thresholdMicros,
        targetMicros: autoRechargeConfig.targetMicros,
      })
      .from(autoRechargeConfig)
      .where(eq(autoRechargeConfig.orgId, orgId)),
  );
  const r = rows[0];
  return {
    enabled: r?.enabled ?? false,
    thresholdMicros: r?.thresholdMicros ?? AUTO_RECHARGE_THRESHOLD_MICROS,
    targetMicros: r?.targetMicros ?? AUTO_RECHARGE_TARGET_MICROS,
  };
}

export async function setAutoRechargeConfig(
  orgId: string,
  cfg: Partial<AutoRechargeConfig> & { enabled: boolean },
): Promise<void> {
  const threshold = cfg.thresholdMicros ?? AUTO_RECHARGE_THRESHOLD_MICROS;
  const target = cfg.targetMicros ?? AUTO_RECHARGE_TARGET_MICROS;
  if (cfg.enabled) validateBounds(threshold, target);
  await withOrg(orgId, (db) =>
    db
      .insert(autoRechargeConfig)
      .values({
        orgId,
        enabled: cfg.enabled,
        thresholdMicros: cfg.thresholdMicros ?? AUTO_RECHARGE_THRESHOLD_MICROS,
        targetMicros: cfg.targetMicros ?? AUTO_RECHARGE_TARGET_MICROS,
        updatedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: autoRechargeConfig.orgId,
        set: {
          enabled: cfg.enabled,
          thresholdMicros: cfg.thresholdMicros ?? AUTO_RECHARGE_THRESHOLD_MICROS,
          targetMicros: cfg.targetMicros ?? AUTO_RECHARGE_TARGET_MICROS,
          updatedAt: new Date(),
        },
      }),
  );
}
