/** Not found / not authorized for this org resource. Surfaced as 404 (never 403)
 *  so a cross-tenant id is not confirmable (no existence oracle). */
export class NotFoundError extends Error {
  constructor(msg = "not found") {
    super(msg);
    this.name = "NotFoundError";
  }
}
