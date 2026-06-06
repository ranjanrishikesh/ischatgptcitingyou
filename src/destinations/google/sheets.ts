/**
 * Google Sheets append client. Used by destinations whose customer has no
 * analytics tool — AI-crawler page views land as rows in their sheet.
 *
 * All requests go through the SSRF-safe egress (Google API hosts are public/443).
 * The access token is a Secret and is only ever placed in the Authorization
 * header at the moment of the call.
 */
import { safeFetch } from "../../egress/safeFetch";
import { Secret } from "../../crypto/secret";
import type { AiEvent } from "../posthog";

const SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets";

export const SHEET_HEADER = ["timestamp", "path", "userAgent", "llm"] as const;

/**
 * Neutralize CSV/formula injection. path + userAgent are attacker-controlled. We
 * write with valueInputOption=RAW so Google does NOT evaluate formulas in-Sheet,
 * but a cell beginning with = + - @ (or TAB/CR) becomes a live formula the moment
 * the customer EXPORTS to CSV/XLSX and opens it in Excel/LibreOffice/Numbers.
 * Prefix a single quote to disarm that downstream hop (OWASP CSV-injection guard).
 */
function csvGuard(s: string): string {
  return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
}

/** Map AI events to sheet rows (with formula-injection neutralization). */
export function eventsToRows(events: AiEvent[]): string[][] {
  return events.map((e) => [
    new Date(e.timestampMs > 0 ? e.timestampMs : Date.now()).toISOString(),
    csvGuard(e.pathname),
    csvGuard(e.userAgent),
    csvGuard(e.llm),
  ]);
}

/** Create a spreadsheet the app owns (drive.file). Returns its id. */
export async function createSpreadsheet(accessToken: Secret<string>, title: string): Promise<string> {
  const res = await safeFetch(SHEETS_API, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken.expose()}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      properties: { title },
      sheets: [{ properties: { title: "Logs" } }],
    }),
  });
  if (!res.ok) throw new Error(`sheets create status ${res.status}`);
  let json: { spreadsheetId?: string };
  try {
    json = JSON.parse(res.body);
  } catch {
    throw new Error("sheets create response: malformed JSON");
  }
  if (!json.spreadsheetId) throw new Error("sheets create: no spreadsheetId");
  return json.spreadsheetId;
}

/** Append rows to a sheet. range e.g. "Logs!A1". */
export async function appendRows(
  accessToken: Secret<string>,
  spreadsheetId: string,
  sheetName: string,
  rows: string[][],
): Promise<void> {
  if (!rows.length) return;
  // A1 notation: sheet names with spaces/specials/leading-digit MUST be single-
  // quoted, with embedded quotes doubled. Single-quoting is always valid, so do
  // it unconditionally — prevents both breakage and range redirection via config.
  const quoted = `'${sheetName.replace(/'/g, "''")}'`;
  const range = encodeURIComponent(`${quoted}!A1`);
  const url = `${SHEETS_API}/${encodeURIComponent(spreadsheetId)}/values/${range}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
  const res = await safeFetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken.expose()}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ values: rows }),
  });
  if (!res.ok) throw new Error(`sheets append status ${res.status}`);
}
