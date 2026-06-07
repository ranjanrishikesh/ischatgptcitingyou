/**
 * Node-only instrumentation. Imported by instrumentation.ts ONLY when
 * NEXT_RUNTIME === "nodejs", so the bundler never pulls the posture probe's
 * node-native deps (postgres -> net/tls) into a non-node bundle. Throwing here
 * fails the boot closed (the intended hosted-posture gate).
 */
import { assertPosture } from "@/config/assertPosture";

await assertPosture();
