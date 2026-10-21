import { add, type Check } from "../lib/types";
import { reverseIPv4, isIPv4 } from "../lib/doh";
import type { Ctx } from "../ctx";

interface List { zone: string; name: string; /** answers that mean "query refused / not usable" */ refused?: (ip: string) => boolean; weak?: boolean }

// Spamhaus refuses queries arriving through public resolvers (1.1.1.1, 8.8.8.8) with 127.255.255.25x.
const spamhausRefused = (ip: string) => /^127\.255\.255\.\d+$/.test(ip);
// SURBL / URIBL answer 127.0.0.1 when the querying resolver is blocked.
const uriRefused = (ip: string) => ip === "127.0.0.1";

const IP_LISTS_BASE: List[] = [
  { zone: "zen.spamhaus.org", name: "Spamhaus ZEN", refused: spamhausRefused },
  { zone: "bl.spamcop.net", name: "SpamCop" },
  { zone: "psbl.surriel.com", name: "PSBL" },
  { zone: "bl.mailspike.net", name: "Mailspike" },
  { zone: "ix.dnsbl.manitu.net", name: "NiX Spam" },
  { zone: "all.s5h.net", name: "s5h" },
  { zone: "dnsbl-1.uceprotect.net", name: "UCEPROTECT L1", weak: true },
];

const DOMAIN_LISTS_BASE: List[] = [
  { zone: "dbl.spamhaus.org", name: "Spamhaus DBL", refused: spamhausRefused },
  { zone: "multi.surbl.org", name: "SURBL", refused: uriRefused },
  { zone: "multi.uribl.com", name: "URIBL", refused: uriRefused },
];

type Verdict = "listed" | "clean" | "unknown";

async function query(ctx: Ctx, name: string, list: List): Promise<{ v: Verdict; codes: string[] }> {
  const r = await ctx.dns.resolve(name, "A");
  if (r.status === -1) return { v: "unknown", codes: [] };
  if (r.status === 3 || !r.records.length) return { v: "clean", codes: [] };
  const codes = r.records;
  if (list.refused && codes.every(list.refused)) return { v: "unknown", codes };
  if (codes.every((c) => !c.startsWith("127."))) return { v: "unknown", codes }; // wildcard/garbage answer
  return { v: "listed", codes };
}

// With a DQS key Spamhaus answers through any resolver: <query>.<key>.zen.dq.spamhaus.net
function withDqs(lists: List[], key?: string): List[] {
  if (!key) return lists;
  return lists.map((l) => l.zone.endsWith(".spamhaus.org")
    ? { ...l, zone: `${key}.${l.zone.replace(/\.spamhaus\.org$/, "")}.dq.spamhaus.net`, name: `${l.name} (DQS)` }
    : l);
}

export async function checkReputation(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];
  const { dns, domain, zone } = ctx;
  const IP_LISTS = withDqs(IP_LISTS_BASE, ctx.dqsKey);
  const DOMAIN_LISTS = withDqs(DOMAIN_LISTS_BASE, ctx.dqsKey);

  // IPs worth checking: the web server and the mail servers.
  const webIps = (await dns.records(domain, "A")).filter(isIPv4).slice(0, 2);
  const mxHosts = (await dns.records(domain, "MX"))
    .map((r) => r.split(/\s+/)[1]?.replace(/\.$/, "")).filter((h): h is string => !!h && h !== "").slice(0, 3);
  const mxIps = (await Promise.all(mxHosts.map((h) => dns.records(h, "A")))).flat().filter(isIPv4);
  const ips = [...new Set([...webIps, ...mxIps])].slice(0, 4);
  const role = (ip: string) => [webIps.includes(ip) && "web", mxIps.includes(ip) && "MX"].filter(Boolean).join("+");

  for (const ip of ips) {
    const res = await Promise.all(IP_LISTS.map(async (l) => ({ l, ...(await query(ctx, `${reverseIPv4(ip)}.${l.zone}`, l)) })));
    const listed = res.filter((r) => r.v === "listed");
    const strong = listed.filter((r) => !r.l.weak);
    const unknown = res.filter((r) => r.v === "unknown");
    add(out, `rep.ip.${ip}`, `IP ${ip} (${role(ip)})`,
      strong.length ? "fail" : listed.length ? "warn" : "ok",
      listed.length ? `na blacklistu: ${listed.map((r) => r.l.name).join(", ")}` : `čistá (${res.length - unknown.length}/${res.length} seznamů ověřeno)`,
      [listed.some((r) => r.l.weak) && "UCEPROTECT L1 je agresivní seznam, většina poskytovatelů ho nepoužívá.",
        unknown.length && `Neověřeno: ${unknown.map((r) => r.l.name).join(", ")} (blokuje dotazy z veřejných resolverů${!ctx.dqsKey && unknown.some((r) => r.l.zone.includes("spamhaus")) ? " — pro Spamhaus nastav DQS klíč" : ""}).`]
        .filter(Boolean).join(" ") || undefined,
      res.map((r) => `${r.l.name.padEnd(14)} ${r.v === "listed" ? "LISTED " + r.codes.join(",") : r.v === "clean" ? "ok" : "nelze ověřit"}`));
  }
  if (!ips.length) add(out, "rep.ip", "IP adresy", "skip", "doména nemá IPv4 adresu ani MX");

  const dres = await Promise.all(DOMAIN_LISTS.map(async (l) => ({ l, ...(await query(ctx, `${zone}.${l.zone}`, l)) })));
  const dListed = dres.filter((r) => r.v === "listed");
  const dUnknown = dres.filter((r) => r.v === "unknown");
  add(out, "rep.domain", `Doména ${zone}`,
    dListed.length ? "fail" : dUnknown.length === dres.length ? "skip" : "ok",
    dListed.length ? `na blacklistu: ${dListed.map((r) => r.l.name).join(", ")}`
      : dUnknown.length === dres.length ? "nelze ověřit" : `čistá (${dres.length - dUnknown.length}/${dres.length} ověřeno)`,
    dUnknown.length ? `Neověřeno: ${dUnknown.map((r) => r.l.name).join(", ")} — tyto seznamy odmítají dotazy z veřejných resolverů.` : undefined,
    dres.map((r) => `${r.l.name.padEnd(14)} ${r.v === "listed" ? "LISTED " + r.codes.join(",") : r.v === "clean" ? "ok" : "nelze ověřit"}`));

  return out;
}
