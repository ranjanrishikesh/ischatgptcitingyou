/**
 * Deployment mode. One codebase, two profiles. `self_host` is the default and
 * runs with zero external SaaS dependency. `hosted` is our multi-tenant platform
 * and MUST satisfy the full security posture before it is allowed to boot
 * (see assertPosture). The same binary; the mode flips the guarantees.
 */

export type DeployMode = "self_host" | "hosted";

export function deployMode(): DeployMode {
  const v = process.env.DEPLOY_MODE ?? "self_host";
  if (v !== "self_host" && v !== "hosted") {
    throw new Error(`Invalid DEPLOY_MODE: ${v} (expected self_host | hosted)`);
  }
  return v;
}

export const isHosted = (): boolean => deployMode() === "hosted";
export const isSelfHost = (): boolean => deployMode() === "self_host";
