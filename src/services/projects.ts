import { eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { project } from "../db/schema";

export async function listProjects(orgId: string) {
  return withOrg(orgId, (db) =>
    db.select({ id: project.id, name: project.name }).from(project).where(eq(project.orgId, orgId)),
  );
}
