import { add, type Check } from "../lib/types";
import { txtValue, isIPv4, type Dns } from "../lib/doh";
import { readText, timedFetch } from "../lib/util";
import type { Ctx } from "../ctx";

const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "dkim", "mail",
  "smtp", "mxvault", "fm1", "zoho", "sig1", "protonmail",
];

async function txt(dns: Dns, name: string): Promise<string[]> {
  return (await dns.records(name, "TXT")).map(txtValue);
}

// ---------------------------------------------------------------- SPF ------
interface SpfWalk { lookups: number; lines: string[]; errors: string[]; warnings: string[] }

async function walkSpf(dns: Dns, domain: string, record: string, w: SpfWalk, depth: number, seen: Set<string>): Promise<void> {
  const indent = "  ".repeat(depth);
  const terms = record.split(/\s+/).slice(1);
  for (const raw of terms) {
    const term = raw.toLowerCase();
    const mech = term.replace(/^[+\-~?]/, "");
    const [name, arg] = mech.split(/[:=]/, 2);
    if (["include", "a", "mx", "ptr", "exists", "redirect"].includes(name.split("/")[0])) w.lookups++;
    if (name === "ptr") w.warnings.push("mechanismus ptr je zastaralý (RFC 7208)");
    if (name === "include" || name === "redirect") {
      const target = arg;
      w.lines.push(`${indent}${raw}`);
      if (!target) continue;
      if (seen.has(target)) { w.errors.push(`smyčka: ${target}`); continue; }
      seen.add(target);
      if (depth > 6) continue;
      const recs = (await txt(dns, target)).filter((t) => /^v=spf1(\s|$)/i.test(t));
      if (!recs.length) {
        w.errors.push(`${name}:${target} nemá SPF záznam (void lookup → permerror)`);
        w.lines.push(`${indent}  ✗ bez SPF`);
        continue;
      }
      await walkSpf(dns, target, recs[0], w, depth + 1, seen);
    } else if (depth === 0) {
      w.lines.push(`${indent}${raw}`);
    }
  }
}

// --------------------------------------------------------------- module ----
export async function checkEmail(ctx: Ctx, dkimSelector?: string): Promise<Check[]> {
  const out: Check[] = [];
  const { dns, domain, zone } = ctx;

  // ---- MX ------------------------------------------------------------------
  const mx = await dns.resolve(domain, "MX");
  const mxList = mx.records
    .map((r) => { const [p, h] = r.split(/\s+/); return { prio: Number(p), host: (h ?? "").replace(/\.$/, "") }; })
    .sort((a, b) => a.prio - b.prio);
  const nullMx = mxList.length === 1 && (mxList[0].host === "" || mxList[0].host === ".");
  if (nullMx) {
    add(out, "email.mx", "MX", "info", "Null MX — doména poštu nepřijímá");
  } else if (!mxList.length) {
    add(out, "email.mx", "MX", "warn", "žádný MX záznam", "Odesílatelé použijí A záznam domény (implicitní MX).");
  } else {
    const rows = await Promise.all(mxList.slice(0, 5).map(async (m) => {
      const [a, cname] = await Promise.all([dns.records(m.host, "A"), dns.records(m.host, "CNAME")]);
      return { ...m, a, cname: cname[0], ip: isIPv4(m.host) };
    }));
    const broken = rows.filter((r) => r.ip || !r.a.length);
    const viaCname = rows.filter((r) => r.cname);
    add(out, "email.mx", "MX", broken.length ? "fail" : viaCname.length ? "warn" : "ok",
      broken.length ? `nefunkční MX: ${broken.map((b) => b.host).join(", ")}`
        : `${mxList.length}× MX${viaCname.length ? ", některé přes CNAME" : ""}`,
      broken.some((b) => b.ip) ? "MX nesmí obsahovat IP adresu, jen hostname."
        : viaCname.length ? "MX by neměl ukazovat na CNAME (RFC 2181)." : undefined,
      rows.map((r) => `${r.prio}  ${r.host}  →  ${r.ip ? "(IP adresa!)" : r.a.join(", ") || "nepřekládá se"}${r.cname ? `  [CNAME ${r.cname}]` : ""}`));
  }

  // ---- SPF -----------------------------------------------------------------
  const spfRecs = (await txt(dns, domain)).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!spfRecs.length) {
    add(out, "email.spf", "SPF", nullMx ? "info" : "warn", "chybí");
  } else if (spfRecs.length > 1) {
    add(out, "email.spf", "SPF", "fail", `${spfRecs.length} SPF záznamy — permerror`, "Doména smí mít jen jeden v=spf1 záznam.", spfRecs);
  } else {
    const rec = spfRecs[0];
    const w: SpfWalk = { lookups: 0, lines: [], errors: [], warnings: [] };
    await walkSpf(dns, domain, rec, w, 0, new Set([domain]));
    const all = rec.match(/\s([+\-~?]?)all\b/i);
    const q = all ? (all[1] || "+") : null;
    const allTxt = q === null ? "bez all" : `${q}all`;
    let status: Check["status"] = "ok";
    const notes: string[] = [];
    if (w.lookups > 10) { status = "fail"; notes.push(`${w.lookups} DNS lookupů (limit 10) → permerror`); }
    if (w.errors.length) { status = "fail"; notes.push(...w.errors); }
    if (q === "+") { status = "fail"; notes.push("+all povoluje odesílat komukoli"); }
    if (q === "?" || q === null) { if (status === "ok") status = "warn"; notes.push(q === null ? "chybí all — výsledek neutral" : "?all = neutral, nic nechrání"); }
    if (w.warnings.length) { if (status === "ok") status = "warn"; notes.push(...new Set(w.warnings)); }
    if (rec.length > 255 * 2) notes.push("dlouhý záznam");
    add(out, "email.spf", "SPF", status, `${allTxt}, ${w.lookups}/10 lookupů`,
      notes.length ? notes.join(" · ") : undefined, [rec, "", ...w.lines]);
  }

  // ---- DMARC ---------------------------------------------------------------
  let dmarcAt = `_dmarc.${domain}`;
  let dmarcRecs = (await txt(dns, dmarcAt)).filter((t) => /^v=DMARC1/i.test(t));
  if (!dmarcRecs.length && zone !== domain) {
    dmarcAt = `_dmarc.${zone}`;
    dmarcRecs = (await txt(dns, dmarcAt)).filter((t) => /^v=DMARC1/i.test(t));
  }
  if (!dmarcRecs.length) {
    add(out, "email.dmarc", "DMARC", "warn", "chybí");
  } else if (dmarcRecs.length > 1) {
    add(out, "email.dmarc", "DMARC", "fail", "více DMARC záznamů — ignorováno", undefined, dmarcRecs);
  } else {
    const rec = dmarcRecs[0];
    const tags = Object.fromEntries(rec.split(";").map((p) => p.trim().split("=").map((x) => x.trim())).filter((p) => p[0]).map(([k, v]) => [k.toLowerCase(), v ?? ""]));
    const p = (tags.p ?? "").toLowerCase();
    const pct = tags.pct ? Number(tags.pct) : 100;
    const notes: string[] = [];
    let status: Check["status"] = p === "reject" || p === "quarantine" ? "ok" : p === "none" ? "warn" : "fail";
    if (!["none", "quarantine", "reject"].includes(p)) notes.push(`neplatná policy p=${tags.p ?? "(chybí)"}`);
    if (p === "none") notes.push("p=none jen monitoruje, nic neblokuje");
    if (pct < 100) notes.push(`pct=${pct} — policy se uplatní jen na část zpráv`);
    if (!tags.rua) notes.push("bez rua — nechodí agregované reporty");

    // External report destinations must authorise receiving reports.
    const ruaDomains = (tags.rua ?? "").split(",").map((u: string) => u.trim().match(/^mailto:[^@]+@([^!\s]+)/i)?.[1]?.toLowerCase()).filter(Boolean) as string[];
    const orgDomain = dmarcAt.replace(/^_dmarc\./, "");
    const external = [...new Set(ruaDomains.filter((d) => d !== orgDomain && !d.endsWith("." + orgDomain)))];
    const extLines: string[] = [];
    for (const d of external.slice(0, 3)) {
      const auth = (await txt(dns, `${orgDomain}._report._dmarc.${d}`)).some((t) => /^v=DMARC1/i.test(t));
      extLines.push(`externí rua ${d}: ${auth ? "autorizováno" : "CHYBÍ autorizace"}`);
      if (!auth) { notes.push(`${d} nepotvrdil příjem reportů (${orgDomain}._report._dmarc.${d})`); if (status === "ok") status = "warn"; }
    }
    add(out, "email.dmarc", "DMARC", status,
      `p=${p || "?"}${tags.sp ? `, sp=${tags.sp}` : ""}${pct < 100 ? `, pct=${pct}` : ""}`,
      [dmarcAt !== `_dmarc.${domain}` ? `zděděno z ${dmarcAt}` : "", ...notes].filter(Boolean).join(" · ") || undefined,
      [rec, "", ...Object.entries(tags).map(([k, v]) => `${k.padEnd(6)} ${v}`), ...extLines]);
  }

  // ---- DKIM ----------------------------------------------------------------
  const selectors = dkimSelector ? [dkimSelector, ...DKIM_SELECTORS.filter((s) => s !== dkimSelector)] : DKIM_SELECTORS;
  const found = (await Promise.all(selectors.map(async (s) => {
    const recs = await txt(dns, `${s}._domainkey.${domain}`);
    const rec = recs.find((r) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(r));
    return rec ? { s, rec } : null;
  }))).filter((x): x is { s: string; rec: string } => !!x);
  if (!found.length) {
    add(out, "email.dkim", "DKIM", "info",
      dkimSelector ? `selektor „${dkimSelector}“ nenalezen` : "žádný z běžných selektorů nenalezen",
      "Selektor se dá zjistit jen z hlavičky DKIM-Signature (s=) v odeslaném e-mailu.", selectors.map((s) => `${s}._domainkey`));
  } else {
    const rows = found.map(({ s, rec }) => {
      const p = rec.match(/p=([^;]*)/i)?.[1]?.replace(/\s+/g, "") ?? "";
      const k = rec.match(/k=([^;]*)/i)?.[1]?.trim() ?? "rsa";
      const bytes = Math.floor((p.length * 3) / 4);
      const bits = k === "rsa" && bytes ? Math.round(((bytes - 38) * 8) / 512) * 512 : undefined;
      return { s, k, p, bits };
    });
    const revoked = rows.filter((r) => !r.p);
    const weak = rows.filter((r) => r.bits && r.bits < 1024);
    add(out, "email.dkim", "DKIM", weak.length ? "fail" : revoked.length === rows.length ? "warn" : rows.some((r) => r.bits === 1024) ? "warn" : "ok",
      rows.map((r) => r.s).join(", "),
      [weak.length && "klíč kratší než 1024 bitů", rows.some((r) => r.bits === 1024) && "1024bitový klíč — doporučeno 2048",
        revoked.length && `zneplatněné (p= prázdné): ${revoked.map((r) => r.s).join(", ")}`].filter(Boolean).join(" · ") || undefined,
      rows.map((r) => `${r.s}._domainkey  ${r.k}${r.bits ? ` ~${r.bits} bit` : ""}${!r.p ? "  (revoked)" : ""}`));
  }

  // ---- MTA-STS / TLS-RPT / BIMI -------------------------------------------
  const [sts, tlsrpt, bimi] = await Promise.all([
    txt(dns, `_mta-sts.${domain}`), txt(dns, `_smtp._tls.${domain}`), txt(dns, `default._bimi.${domain}`),
  ]);
  const stsRec = sts.find((t) => /^v=STSv1/i.test(t));
  if (!stsRec) {
    add(out, "email.mtasts", "MTA-STS", "info", "nenastaveno");
  } else {
    let policy = "";
    let status: Check["status"] = "ok";
    let note: string | undefined;
    try {
      const r = await timedFetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { redirect: "manual" }, 6000);
      policy = r.status === 200 ? await readText(r, 8192) : "";
      if (r.status !== 200) { status = "fail"; note = `policy soubor vrací HTTP ${r.status}`; }
    } catch (e) {
      status = "fail"; note = `policy soubor nedostupný: ${(e as Error).message}`;
    }
    const mode = policy.match(/^mode:\s*(\w+)/im)?.[1];
    const patterns = [...policy.matchAll(/^mx:\s*(\S+)/gim)].map((m) => m[1].toLowerCase());
    const uncovered = mxList.filter((m) => !patterns.some((p) => p === m.host || (p.startsWith("*.") && m.host.endsWith(p.slice(1)))));
    if (policy && uncovered.length && mode === "enforce") { status = "fail"; note = `MX mimo policy: ${uncovered.map((u) => u.host).join(", ")}`; }
    else if (policy && mode !== "enforce" && status === "ok") note = `mode=${mode ?? "?"}`;
    add(out, "email.mtasts", "MTA-STS", status, mode ? `mode=${mode}` : "TXT existuje", note,
      [stsRec, "", ...policy.split(/\r?\n/).filter(Boolean)]);
  }
  const rpt = tlsrpt.find((t) => /^v=TLSRPTv1/i.test(t));
  add(out, "email.tlsrpt", "TLS-RPT", "info", rpt ? "nastaveno" : "nenastaveno", undefined, rpt ? [rpt] : undefined);
  const bimiRec = bimi.find((t) => /^v=BIMI1/i.test(t));
  add(out, "email.bimi", "BIMI", "info", bimiRec ? "nastaveno" : "nenastaveno", undefined, bimiRec ? [bimiRec] : undefined);

  return out;
}
