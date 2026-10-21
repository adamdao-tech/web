import { add, type Check } from "../lib/types";
import { parseCaa, RCODE, RR, type CaaRecord, type Dns } from "../lib/doh";
import { queryDirect } from "../lib/dnswire";
import { socketError } from "../lib/tcp";
import { isCloudflareIp } from "../lib/cloudflare";
import { randomLabel } from "../lib/util";
import type { Ctx } from "../ctx";

export async function checkDns(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];
  const { dns, domain, zone } = ctx;

  // --- Resolution -----------------------------------------------------------
  const [a, aaaa, cname] = await Promise.all([
    dns.resolve(domain, "A"), dns.resolve(domain, "AAAA"), dns.resolve(domain, "CNAME"),
  ]);
  if (a.status === -1) {
    add(out, "dns.resolve", "Překlad domény", "fail", "DoH resolver nedostupný", a.error);
    return out;
  }
  if (a.status === 3) {
    add(out, "dns.resolve", "Překlad domény", "fail", "NXDOMAIN — doména neexistuje");
    return out;
  }
  const items = [
    ...cname.records.map((r) => `CNAME ${r}`),
    ...a.records.map((r) => `A     ${r}`),
    ...aaaa.records.map((r) => `AAAA  ${r}`),
  ];
  if (a.status === 2) {
    const cd = await dns.resolve(domain, "A", true);
    add(out, "dns.resolve", "Překlad domény", "fail",
      cd.status === 0 ? "SERVFAIL — rozbitý DNSSEC (bez validace odpovídá)" : "SERVFAIL",
      cd.status === 0 ? "S vypnutou validací (cd=1) resolver odpoví, problém je v podpisech DNSSEC." : undefined,
      cd.records.map((r) => `A     ${r}`));
  } else if (!a.records.length && !aaaa.records.length) {
    add(out, "dns.resolve", "Překlad domény", "fail", "žádný A ani AAAA záznam", undefined, items);
  } else {
    add(out, "dns.resolve", "Překlad domény", "ok",
      `${a.records.length}× A, ${aaaa.records.length}× AAAA`, undefined, items);
  }
  add(out, "dns.ipv6", "IPv6 (AAAA)", aaaa.records.length ? "ok" : "info",
    aaaa.records.length ? aaaa.records.join(", ") : "bez AAAA záznamu");

  // www variant (only when checking the apex)
  if (!domain.startsWith("www.") && domain === zone) {
    const w = await dns.resolve("www." + domain, "A");
    const wc = await dns.resolve("www." + domain, "CNAME");
    const recs = [...wc.records.map((r) => `CNAME ${r}`), ...w.records.map((r) => `A ${r}`)];
    add(out, "dns.www", `www.${domain}`, w.records.length ? "ok" : "warn",
      w.records.length ? "překládá se" : "nepřekládá se", undefined, recs);
  }

  // --- NS + SOA consistency ------------------------------------------------
  const ns = await dns.resolve(zone, "NS");
  const nsNames = ns.records.map((r) => r.replace(/\.$/, "").toLowerCase()).sort();
  if (!nsNames.length) {
    add(out, "dns.ns", "Nameservery", "fail", `zóna ${zone} nemá NS záznamy`);
  } else {
    add(out, "dns.ns", "Nameservery", nsNames.length >= 2 ? "ok" : "warn",
      `${nsNames.length}× NS (zóna ${zone})`,
      nsNames.length < 2 ? "RFC 1034 doporučuje alespoň 2 nameservery." : undefined, nsNames);
  }

  const soa = await dns.resolve(zone, "SOA");
  const soaRec = soa.records[0];
  if (soaRec) {
    const f = soaRec.split(/\s+/);
    add(out, "dns.soa", "SOA", "info", `serial ${f[2]}`, undefined, [
      `primary NS  ${f[0]}`, `hostmaster  ${f[1]}`, `serial      ${f[2]}`,
      `refresh     ${f[3]}`, `retry       ${f[4]}`, `expire      ${f[5]}`, `min TTL     ${f[6]}`,
    ]);
  }

  if (nsNames.length) {
    const rows = await Promise.all(nsNames.map(async (n) => {
      const ips = (await dns.resolve(n, "A")).records;
      if (!ips.length) return { n, ip: "-", err: "NS nemá A záznam" };
      if (isCloudflareIp(ips[0])) return { n, ip: ips[0], err: "Cloudflare NS — z Workeru nelze dotázat přímo", cf: true };
      try {
        const r = await queryDirect(ips[0], zone, RR.SOA);
        return { n, ip: ips[0], serial: r.soaSerial, aa: r.aa, rcode: r.rcode };
      } catch (e) {
        return { n, ip: ips[0], err: socketError(e) };
      }
    }));
    const answered = rows.filter((r) => r.serial !== undefined);
    const lame = rows.filter((r) => r.err === undefined && (r.rcode !== 0 || !r.aa));
    const serials = new Set(answered.map((r) => r.serial));
    const lines = rows.map((r) => r.err
      ? `${r.n} (${r.ip})  ✗ ${r.err}`
      : `${r.n} (${r.ip})  serial ${r.serial ?? "-"}  ${r.aa ? "AA" : "NE-autoritativní"}  ${RCODE[r.rcode!] ?? r.rcode}`);

    if (!answered.length && !lame.length) {
      const cf = rows.every((r) => (r as { cf?: boolean }).cf);
      add(out, "dns.ns-consistency", "Konzistence NS", cf ? "info" : "warn",
        cf ? "Cloudflare DNS — konzistenci zajišťuje Cloudflare" : "žádný nameserver neodpověděl na přímý dotaz",
        cf ? "Workers se nemohou přímo připojit na IP adresy Cloudflare." : rows[0]?.err, lines);
    } else if (lame.length) {
      add(out, "dns.ns-consistency", "Konzistence NS", "fail",
        `lame delegation: ${lame.map((r) => r.n).join(", ")}`,
        "NS je delegovaný, ale neodpovídá autoritativně pro zónu.", lines);
    } else if (serials.size > 1) {
      add(out, "dns.ns-consistency", "Konzistence NS", "warn",
        `rozdílné SOA serialy (${[...serials].join(" / ")})`,
        "Sekundární NS nemusí mít aktuální zónu (selhaný transfer).", lines);
    } else {
      const skipped = rows.length - answered.length;
      add(out, "dns.ns-consistency", "Konzistence NS", "ok",
        `${answered.length} NS se shodují${skipped ? `, ${skipped} nedotázáno` : ""}`, undefined, lines);
    }
  }

  // --- DNSSEC ---------------------------------------------------------------
  const [ds, dnskey] = await Promise.all([dns.resolve(zone, "DS"), dns.resolve(zone, "DNSKEY")]);
  const dnssecItems = [
    ...ds.records.map((r) => `DS      ${r}`),
    ...dnskey.records.map((r) => `DNSKEY  ${r.length > 70 ? r.slice(0, 70) + "…" : r}`),
  ];
  if (!ds.records.length && !dnskey.records.length) {
    add(out, "dns.dnssec", "DNSSEC", "info", "zóna není podepsaná");
  } else if (!ds.records.length) {
    add(out, "dns.dnssec", "DNSSEC", "warn", "DNSKEY existuje, ale chybí DS u registru",
      "Zóna je podepsaná, ale řetězec důvěry není navázaný — DNSSEC se neuplatní.", dnssecItems);
  } else if (!dnskey.records.length) {
    add(out, "dns.dnssec", "DNSSEC", "fail", "DS u registru, ale zóna nemá DNSKEY",
      "Validující resolvery budou vracet SERVFAIL.", dnssecItems);
  } else if (a.status === 2 || dnskey.status === 2) {
    add(out, "dns.dnssec", "DNSSEC", "fail", "podpisy neprochází validací (bogus)", undefined, dnssecItems);
  } else {
    add(out, "dns.dnssec", "DNSSEC", a.ad || dnskey.ad ? "ok" : "warn",
      a.ad || dnskey.ad ? "podepsáno a validní (AD)" : "DS i DNSKEY existují, resolver nenastavil AD",
      undefined, dnssecItems);
  }

  // --- CAA ------------------------------------------------------------------
  const { at: caaAt, records: caa } = await findCaa(dns, domain);
  if (!caa.length) {
    add(out, "dns.caa", "CAA", "info", "bez CAA — certifikát může vydat jakákoli CA");
  } else {
    add(out, "dns.caa", "CAA", "ok",
      `povolené CA: ${caa.filter((c) => c.tag === "issue").map((c) => c.value || "(žádná)").join(", ") || "-"}`,
      caaAt !== domain ? `zděděno z ${caaAt}` : undefined,
      caa.map((c) => `${c.flags} ${c.tag} "${c.value}"`));
  }

  // --- Wildcard -------------------------------------------------------------
  const wc = await dns.resolve(`${randomLabel()}.${domain}`, "A");
  add(out, "dns.wildcard", "Wildcard záznam", wc.records.length ? "info" : "ok",
    wc.records.length ? `*.${domain} → ${wc.records.join(", ")}` : "není");

  // --- HTTPS RR -------------------------------------------------------------
  const https = await dns.resolve(domain, "HTTPS");
  if (https.records.length) {
    add(out, "dns.httpsrr", "HTTPS/SVCB záznam", "info", "přítomen", undefined, https.records);
  }

  return out;
}

/** Relevant CAA set for a host: climb towards the root until a CAA RRset is found (RFC 8659). */
export async function findCaa(dns: Dns, host: string): Promise<{ at: string; records: CaaRecord[] }> {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join(".");
    const r = await dns.resolve(name, "CAA");
    const recs = r.records.map(parseCaa).filter((c): c is CaaRecord => !!c);
    if (recs.length) return { at: name, records: recs };
  }
  return { at: "", records: [] };
}
