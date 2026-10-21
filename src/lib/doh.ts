// DNS-over-HTTPS (JSON API) client with resolver fallback.

export const RR: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  DS: 43, DNSKEY: 48, TLSA: 52, HTTPS: 65, CAA: 257,
};

export interface Answer { name: string; type: number; ttl: number; data: string }
export interface DnsResult {
  /** RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN … ; -1 = transport error */
  status: number;
  ad: boolean;
  answers: Answer[];
  /** answers filtered to the requested type */
  records: string[];
  resolver: string;
  error?: string;
}

const RESOLVERS = [
  { name: "cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { name: "google", url: "https://dns.google/resolve" },
];

export const RCODE: Record<number, string> = {
  0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
};

/**
 * Request-scoped resolver with a small cache. Workers forbid awaiting I/O started by
 * another request, so a fresh instance is created for every incoming request and
 * shared by all modules of that request (several of them ask for A/MX/TXT…).
 */
export class Dns {
  private cache = new Map<string, Promise<DnsResult>>();

  /** cd = "checking disabled": ask the resolver to skip DNSSEC validation. */
  resolve(name: string, type: keyof typeof RR | string, cd = false): Promise<DnsResult> {
    const key = `${name.toLowerCase()}|${type}|${cd ? 1 : 0}`;
    let p = this.cache.get(key);
    if (!p) {
      p = doResolve(name, type, cd);
      this.cache.set(key, p);
    }
    return p;
  }

  /** Convenience: records of a type, [] on any error. */
  async records(name: string, type: string): Promise<string[]> {
    return (await this.resolve(name, type)).records;
  }
}

async function doResolve(name: string, type: string, cd: boolean): Promise<DnsResult> {
  const typeNum = RR[type] ?? Number(type);
  let lastErr = "";
  for (const r of RESOLVERS) {
    try {
      const u = new URL(r.url);
      u.searchParams.set("name", name);
      u.searchParams.set("type", String(typeNum));
      u.searchParams.set("do", "1");
      if (cd) u.searchParams.set("cd", "1");
      const res = await fetch(u.toString(), {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(6000),
      });
      if (!res.ok) { lastErr = `${r.name} HTTP ${res.status}`; continue; }
      const j = (await res.json()) as {
        Status: number; AD?: boolean; Answer?: Answer[];
      };
      const answers = (j.Answer ?? []).map((a) => ({ ...a, name: a.name.replace(/\.$/, "") }));
      return {
        status: j.Status,
        ad: !!j.AD,
        answers,
        records: answers.filter((a) => a.type === typeNum).map((a) => a.data),
        resolver: r.name,
      };
    } catch (e) {
      lastErr = `${r.name}: ${(e as Error).message}`;
    }
  }
  return { status: -1, ad: false, answers: [], records: [], resolver: "none", error: lastErr };
}

/** Join TXT character-strings: `"v=spf1 a" " mx"` -> `v=spf1 a mx`. */
export function txtValue(data: string): string {
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!parts) return data;
  return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}

export interface CaaRecord { flags: number; tag: string; value: string }

/** Parse CAA in presentation format (`0 issue "x"`) or RFC 3597 generic (`\# 22 00 05 ...`). */
export function parseCaa(data: string): CaaRecord | null {
  const generic = data.match(/^\\#\s+\d+\s+([0-9a-fA-F\s]+)$/);
  if (generic) {
    const bytes = generic[1].replace(/\s+/g, "").match(/../g)?.map((h) => parseInt(h, 16)) ?? [];
    if (bytes.length < 2) return null;
    const flags = bytes[0];
    const tagLen = bytes[1];
    const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
    const value = String.fromCharCode(...bytes.slice(2 + tagLen));
    return { flags, tag: tag.toLowerCase(), value };
  }
  const m = data.match(/^(\d+)\s+(\S+)\s+"?(.*?)"?$/);
  if (!m) return null;
  return { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3] };
}

export function reverseIPv4(ip: string): string {
  return ip.split(".").reverse().join(".");
}

export function isIPv4(s: string): boolean {
  return /^(\d{1,3})(\.\d{1,3}){3}$/.test(s);
}
