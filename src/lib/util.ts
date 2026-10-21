import type { Dns } from "./doh";

export const UA = "Mozilla/5.0 (compatible; webcheck/0.1; +https://github.com/adamdao-tech/web)";

/** Accepts "https://Example.com/path", "example.com:8080", IDN… returns ASCII hostname or null. */
export function normalizeDomain(input: string): string | null {
  let s = (input || "").trim();
  if (!s) return null;
  if (!/^[a-z]+:\/\//i.test(s)) s = "http://" + s;
  try {
    const u = new URL(s);
    const h = u.hostname.replace(/\.$/, "").toLowerCase();
    if (!/^[a-z0-9.-]+$/.test(h) || !h.includes(".") || h.length > 253) return null;
    if (/^\d+(\.\d+){3}$/.test(h)) return null; // IP addresses not supported
    return h;
  } catch {
    return null;
  }
}

/** Find the zone apex (first ancestor that has NS records). */
export async function findZone(dns: Dns, host: string): Promise<string> {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const cand = labels.slice(i).join(".");
    const r = await dns.resolve(cand, "NS");
    if (r.records.length) return cand;
  }
  return labels.slice(-2).join(".");
}

export async function timedFetch(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("user-agent")) headers.set("user-agent", UA);
  return fetch(url, { ...init, headers, signal: AbortSignal.timeout(timeoutMs) });
}

/** Read at most `max` bytes of a body as text. */
export async function readText(res: Response, max = 512 * 1024): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, max));
  let o = 0;
  for (const c of chunks) {
    const part = c.subarray(0, all.length - o);
    all.set(part, o);
    o += part.length;
    if (o >= all.length) break;
  }
  return new TextDecoder("utf-8").decode(all);
}

export function daysUntil(d: Date): number {
  return Math.floor((d.getTime() - Date.now()) / 86_400_000);
}

export function fmtDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function randomLabel(): string {
  return "wc-" + Math.random().toString(36).slice(2, 12);
}
