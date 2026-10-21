import { add, type Check } from "../lib/types";
import { probeTls, TLS10, TLS11, TLS12, TLS13, VERSION_NAME, CIPHER_NAME, type HandshakeResult } from "../lib/tls";
import { parseCert, certCovers, nameLabel, type Cert } from "../lib/x509";
import { daysUntil, fmtDate, timedFetch } from "../lib/util";
import { findCaa } from "./dns";
import { isCloudflareIp } from "../lib/cloudflare";
import type { Ctx } from "../ctx";

/** Issuer organisation → CAA identifiers that authorise it. */
const CA_DOMAINS: [RegExp, string[]][] = [
  [/let'?s encrypt/i, ["letsencrypt.org"]],
  [/digicert|geotrust|thawte|rapidssl|symantec|encryption everywhere/i, ["digicert.com", "symantec.com", "geotrust.com", "thawte.com", "rapidssl.com"]],
  [/sectigo|comodo|zerossl/i, ["sectigo.com", "comodoca.com", "comodo.com", "zerossl.com", "usertrust.com", "trust-provider.com"]],
  [/globalsign/i, ["globalsign.com"]],
  [/google trust services/i, ["pki.goog"]],
  [/amazon/i, ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"]],
  [/entrust/i, ["entrust.net"]],
  [/buypass/i, ["buypass.com", "buypass.no"]],
  [/certum|asseco/i, ["certum.pl"]],
  [/godaddy|starfield/i, ["godaddy.com", "starfieldtech.com"]],
  [/actalis/i, ["actalis.it"]],
  [/ssl\.com/i, ["ssl.com"]],
  [/microsoft/i, ["microsoft.com"]],
];

export async function checkSsl(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];
  const { domain, base, dns } = ctx;

  const ips = await dns.records(domain, "A");
  const behindCf = ips.length > 0 && ips.every(isCloudflareIp);
  if (behindCf) return cloudflareFallback(out, domain, ips);

  const [p12, p13, p11, p10] = await Promise.all([
    probeTls(domain, domain, TLS12),
    probeTls(domain, domain, TLS13),
    probeTls(domain, domain, TLS11),
    probeTls(domain, domain, TLS10),
  ]);

  // ---- Could we read the chain at all? -------------------------------------
  if (!p12.certs.length) {
    const reason = p12.error ?? p12.alert ?? "server neposlal certifikát";
    // Fall back to a plain HTTPS request: tells us at least whether the cert validates.
    let fetchVerdict: { ok: boolean; msg: string };
    try {
      const r = await timedFetch(`https://${domain}/`, { redirect: "manual", method: "HEAD" });
      fetchVerdict = { ok: true, msg: `HTTPS odpovídá (${r.status}), certifikát přijat` };
    } catch (e) {
      fetchVerdict = { ok: false, msg: (e as Error).message };
    }
    if (p13.ok && !p12.ok) {
      add(out, "ssl.chain", "Certifikát", fetchVerdict.ok ? "info" : "fail",
        fetchVerdict.ok ? "server umí jen TLS 1.3 — řetězec nelze vyčíst" : `HTTPS selhalo: ${fetchVerdict.msg}`,
        "U TLS 1.3 je certifikát šifrovaný, detaily (řetězec, expirace) proto nejsou dostupné.");
    } else {
      add(out, "ssl.chain", "Certifikát", fetchVerdict.ok ? "warn" : "fail",
        fetchVerdict.ok ? fetchVerdict.msg : `HTTPS selhalo: ${fetchVerdict.msg}`,
        `Přímý TLS handshake selhal: ${reason}`);
    }
    versionsCheck(out, [p10, p11, p12, p13]);
    return out;
  }

  const certs: Cert[] = await Promise.all(p12.certs.map(parseCert));
  const leaf = certs[0];

  // ---- Expiry --------------------------------------------------------------
  const days = daysUntil(leaf.notAfter);
  const notYet = leaf.notBefore.getTime() > Date.now();
  add(out, "ssl.expiry", "Platnost", notYet || days < 0 ? "fail" : days <= 7 ? "fail" : days <= 21 ? "warn" : "ok",
    notYet ? `platný až od ${fmtDate(leaf.notBefore)}`
      : days < 0 ? `EXPIROVANÝ (${fmtDate(leaf.notAfter)})`
      : `ještě ${days} dní (do ${fmtDate(leaf.notAfter)})`,
    undefined, [`notBefore ${leaf.notBefore.toISOString()}`, `notAfter  ${leaf.notAfter.toISOString()}`]);

  // ---- Hostname coverage ---------------------------------------------------
  const names = leaf.dnsNames.length ? leaf.dnsNames : leaf.subject.CN ? [leaf.subject.CN] : [];
  const other = domain.startsWith("www.") ? base : `www.${domain}`;
  const coversMain = certCovers(names, domain);
  const coversOther = certCovers(names, other);
  const otherResolves = (await dns.records(other, "A")).length > 0;
  add(out, "ssl.hostname", "Pokrytí domény (SAN)",
    !coversMain ? "fail" : !coversOther && otherResolves ? "warn" : "ok",
    !coversMain ? `certifikát NEPOKRÝVÁ ${domain}`
      : !coversOther && otherResolves ? `chybí ${other} (přitom se překládá)`
      : coversOther ? `${domain} i ${other}` : domain,
    `${names.length} jmen v SAN`, names);

  // ---- Chain ---------------------------------------------------------------
  const chainLines = certs.map((c, i) =>
    `[${i}] ${nameLabel(c.subject)}  ←  ${nameLabel(c.issuer)}   exp ${fmtDate(c.notAfter)}   ${c.keyType}${c.keyBits ? " " + c.keyBits : ""}${c.selfSigned ? "   (root)" : ""}`);
  const orderBroken = certs.slice(0, -1).findIndex((c, i) => c.issuerRaw !== certs[i + 1].subjectRaw);
  const expiredInter = certs.slice(1).filter((c) => daysUntil(c.notAfter) < 0);
  if (leaf.selfSigned) {
    add(out, "ssl.chain", "Řetězec", "fail", "self-signed certifikát", undefined, chainLines);
  } else if (certs.length === 1) {
    add(out, "ssl.chain", "Řetězec", "fail", "chybí intermediate certifikát",
      `Server posílá jen koncový certifikát (vydavatel: ${nameLabel(leaf.issuer)}). Prohlížeče si ho často dohledají, curl, Java, Android a e-mailoví klienti ne.`,
      chainLines);
  } else if (orderBroken >= 0) {
    add(out, "ssl.chain", "Řetězec", "warn", `špatné pořadí / nesouvisející cert na pozici ${orderBroken + 1}`,
      "Každý certifikát má být následován svým vydavatelem.", chainLines);
  } else if (expiredInter.length) {
    add(out, "ssl.chain", "Řetězec", "fail", `expirovaný intermediate: ${nameLabel(expiredInter[0].subject)}`, undefined, chainLines);
  } else {
    const root = certs[certs.length - 1].selfSigned;
    add(out, "ssl.chain", "Řetězec", "ok",
      `kompletní (${certs.length} cert.)${root ? ", posílá i root" : ""}`,
      root ? "Posílat root není chyba, jen zbytečně zvětšuje handshake." : undefined, chainLines);
  }

  // ---- Issuer / key / signature -------------------------------------------
  add(out, "ssl.issuer", "Vydavatel", "info", `${leaf.issuer.O ?? ""} ${leaf.issuer.CN ? "(" + leaf.issuer.CN + ")" : ""}`.trim(),
    undefined, [`subject  ${Object.entries(leaf.subject).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `issuer   ${Object.entries(leaf.issuer).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `serial   ${leaf.serial}`, `SHA-256  ${leaf.sha256}`,
      ...leaf.ocsp.map((u) => `OCSP     ${u}`), ...leaf.caIssuers.map((u) => `CA Issuers ${u}`)]);

  const weakKey = leaf.keyType === "RSA" && (leaf.keyBits ?? 0) < 2048;
  const weakSig = /sha1/i.test(leaf.sigAlg);
  add(out, "ssl.key", "Klíč a podpis", weakKey || weakSig ? "fail" : "ok",
    `${leaf.keyType}${leaf.keyBits ? " " + leaf.keyBits + " bit" : ""}, ${leaf.sigAlg}`,
    weakKey ? "RSA klíč kratší než 2048 bitů." : weakSig ? "SHA-1 podpis už prohlížeče nepřijímají." : undefined);

  // ---- CAA vs issuer -------------------------------------------------------
  const caa = await findCaa(dns, domain);
  const issueTags = caa.records.filter((c) => c.tag === "issue").map((c) => c.value.split(";")[0].trim().toLowerCase());
  if (caa.records.length && issueTags.length) {
    const issuerText = `${leaf.issuer.O ?? ""} ${leaf.issuer.CN ?? ""}`;
    const known = CA_DOMAINS.find(([re]) => re.test(issuerText));
    if (!known) {
      add(out, "ssl.caa", "CAA vs. vydavatel", "info", `nelze automaticky spárovat (${nameLabel(leaf.issuer)})`, undefined, issueTags);
    } else {
      const okCaa = issueTags.some((t) => known[1].includes(t));
      add(out, "ssl.caa", "CAA vs. vydavatel", okCaa ? "ok" : "warn",
        okCaa ? "vydavatel je v CAA povolen" : `CAA nepovoluje aktuální CA (${nameLabel(leaf.issuer)})`,
        okCaa ? undefined : "Obnova certifikátu u stávající CA selže, dokud se CAA neupraví.", issueTags);
    }
  }

  // ---- Protocols / cipher / OCSP ------------------------------------------
  versionsCheck(out, [p10, p11, p12, p13]);

  if (p12.cipher !== undefined) {
    const name = CIPHER_NAME[p12.cipher] ?? `0x${p12.cipher.toString(16)}`;
    const noPfs = !/ECDHE|DHE/.test(name);
    add(out, "ssl.cipher", "Šifra (TLS 1.2)", /DES|RC4/.test(name) ? "fail" : noPfs ? "warn" : "ok", name,
      noPfs ? "Bez forward secrecy (server preferuje statickou RSA výměnu klíčů)." : undefined);
  }
  add(out, "ssl.ocsp", "OCSP stapling", "info", p12.ocspStapled ? "zapnuto" : "vypnuto");

  return out;
}

function versionsCheck(out: Check[], probes: HandshakeResult[]): void {
  const vers = [TLS10, TLS11, TLS12, TLS13];
  const supported = vers.filter((v, i) => probes[i].ok && probes[i].version === v);
  const lines = vers.map((v, i) => {
    const p = probes[i];
    const yes = p.ok && p.version === v;
    return `${VERSION_NAME[v]}  ${yes ? "ANO" : "ne"}${!yes && (p.alert || p.error) ? `  (${p.alert ?? p.error})` : ""}`;
  });
  if (!supported.length) {
    const noConnect = probes.every((p) => p.error && !p.alert);
    add(out, "ssl.versions", "Verze TLS", noConnect ? "warn" : "fail",
      noConnect ? `port 443 nedostupný (${probes[0].error})` : "žádná verze TLS neprošla", undefined, lines);
    return;
  }
  const legacy = supported.filter((v) => v < TLS12);
  add(out, "ssl.versions", "Verze TLS", legacy.length ? "warn" : "ok",
    supported.map((v) => VERSION_NAME[v]).join(", "),
    legacy.length ? `Zastaralé protokoly ${legacy.map((v) => VERSION_NAME[v]).join(", ")} jsou zapnuté.`
      : !supported.includes(TLS13) ? "TLS 1.3 není podporováno." : undefined,
    lines);
}

/** Site proxied by Cloudflare: raw sockets are not allowed, validate via HTTPS only. */
async function cloudflareFallback(out: Check[], domain: string, ips: string[]): Promise<Check[]> {
  try {
    const r = await timedFetch(`https://${domain}/`, { redirect: "manual", method: "HEAD" });
    add(out, "ssl.chain", "Certifikát", "ok", `platný (HTTPS odpovídá ${r.status})`,
      "Doména je za Cloudflare proxy — návštěvníci vidí certifikát Cloudflare (Universal/Advanced SSL), ne certifikát originu. Řetězec a verze TLS z Workeru nejde přímo vyčíst.",
      ips.map((ip) => `A ${ip}  (Cloudflare)`));
  } catch (e) {
    add(out, "ssl.chain", "Certifikát", "fail", `HTTPS selhalo: ${(e as Error).message}`,
      "Doména je za Cloudflare proxy.", ips.map((ip) => `A ${ip}  (Cloudflare)`));
  }
  add(out, "ssl.versions", "Verze TLS", "info", "řídí Cloudflare (SSL/TLS → Edge Certificates → Minimum TLS Version)");
  return out;
}
