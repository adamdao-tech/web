import { add, type Check } from "../lib/types";
import { timedFetch } from "../lib/util";
import type { Ctx } from "../ctx";

interface Hop { url: string; status: number; location?: string; ms: number; error?: string }

async function follow(start: string, max = 10): Promise<{ hops: Hop[]; final?: Response; loop: boolean }> {
  const hops: Hop[] = [];
  const seen = new Set<string>();
  let url = start;
  for (let i = 0; i <= max; i++) {
    if (seen.has(url)) return { hops, loop: true };
    seen.add(url);
    const t0 = Date.now();
    let res: Response;
    try {
      res = await timedFetch(url, { redirect: "manual" });
    } catch (e) {
      hops.push({ url, status: 0, ms: Date.now() - t0, error: (e as Error).message });
      return { hops, loop: false };
    }
    const ms = Date.now() - t0;
    const loc = res.headers.get("location") ?? undefined;
    hops.push({ url, status: res.status, location: loc, ms });
    if (res.status >= 300 && res.status < 400 && loc) {
      res.body?.cancel().catch(() => {});
      url = new URL(loc, url).toString();
      continue;
    }
    return { hops, final: res, loop: false };
  }
  return { hops, loop: true };
}

const fmtHops = (h: Hop[]) => h.map((x) =>
  x.error ? `${x.url}  ✗ ${x.error}` : `${x.status}  ${x.url}${x.location ? "  →" : ""}  (${x.ms} ms)`);

export async function checkHttp(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];
  const { domain, base, dns } = ctx;
  const www = `www.${base}`;
  const wwwResolves = (await dns.records(www, "A")).length > 0 || (await dns.records(www, "CNAME")).length > 0;
  const hosts = domain === base && wwwResolves ? [base, www] : [domain];

  const starts = hosts.flatMap((h) => [`http://${h}/`, `https://${h}/`]);
  const chains = await Promise.all(starts.map((s) => follow(s)));
  const byStart = new Map(starts.map((s, i) => [s, chains[i]]));

  // ---- HTTP -> HTTPS -------------------------------------------------------
  const httpChain = byStart.get(`http://${domain}/`)!;
  const httpFinal = httpChain.hops[httpChain.hops.length - 1];
  if (httpChain.loop) {
    add(out, "http.redirect", "HTTP → HTTPS", "fail", "smyčka přesměrování", undefined, fmtHops(httpChain.hops));
  } else if (httpFinal?.error) {
    add(out, "http.redirect", "HTTP → HTTPS", "warn", "HTTP (port 80) neodpovídá", httpFinal.error);
  } else {
    const toHttps = httpFinal.url.startsWith("https://");
    const firstIsPermanent = [301, 308].includes(httpChain.hops[0].status);
    add(out, "http.redirect", "HTTP → HTTPS", !toHttps ? "fail" : firstIsPermanent ? "ok" : "warn",
      !toHttps ? "HTTP NEpřesměrovává na HTTPS" : `přesměrováno (${httpChain.hops[0].status})`,
      toHttps && !firstIsPermanent ? "Pro trvalé přesměrování je vhodnější 301/308." : undefined,
      fmtHops(httpChain.hops));
  }

  // ---- Canonical host (www vs. apex) --------------------------------------
  const finals = chains
    .map((c) => c.hops[c.hops.length - 1])
    .filter((h) => h && !h.error && h.status < 400)
    .map((h) => { try { return new URL(h.url).origin; } catch { return h.url; } });
  const uniq = [...new Set(finals)];
  const allLines = starts.flatMap((s) => [`# ${s}`, ...fmtHops(byStart.get(s)!.hops)]);
  const longest = Math.max(...chains.map((c) => c.hops.length - 1));
  if (hosts.length > 1) {
    add(out, "http.canonical", "Kanonická adresa (www / bez www)",
      uniq.length === 1 ? (longest > 2 ? "warn" : "ok") : "warn",
      uniq.length === 1 ? `vše končí na ${uniq[0]}` : `obsah na více adresách: ${uniq.join(", ")}`,
      uniq.length > 1 ? "www i varianta bez www odpovídají samostatně — duplicitní obsah, rozdělené cookies."
        : longest > 2 ? `Nejdelší řetězec má ${longest} přesměrování.` : undefined,
      allLines);
  } else {
    add(out, "http.chains", "Přesměrování", longest > 2 ? "warn" : "info",
      `max. ${longest} přesměrování`, undefined, allLines);
  }

  // ---- Final response ------------------------------------------------------
  const httpsChain = byStart.get(`https://${domain}/`)!;
  const fin = httpsChain.final;
  const lastHop = httpsChain.hops[httpsChain.hops.length - 1];
  if (!fin) {
    add(out, "http.status", "HTTPS odpověď", "fail",
      httpsChain.loop ? "smyčka přesměrování" : lastHop?.error ?? "bez odpovědi", undefined, fmtHops(httpsChain.hops));
    return out;
  }
  fin.body?.cancel().catch(() => {});
  const totalMs = httpsChain.hops.reduce((s, h) => s + h.ms, 0);
  add(out, "http.status", "HTTPS odpověď", fin.status < 400 ? "ok" : fin.status < 500 ? "warn" : "fail",
    `${fin.status} ${fin.statusText} — ${lastHop.url}`);
  add(out, "http.time", "Doba odpovědi", lastHop.ms > 2000 ? "warn" : "info",
    `${lastHop.ms} ms (celkem s redirecty ${totalMs} ms)`, "Měřeno z Cloudflare edge, včetně TCP/TLS.");

  const h = fin.headers;

  // ---- Security headers ----------------------------------------------------
  const hsts = h.get("strict-transport-security");
  if (!hsts) {
    add(out, "http.hsts", "HSTS", "warn", "chybí");
  } else {
    const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
    const flags = [/includesubdomains/i.test(hsts) && "includeSubDomains", /preload/i.test(hsts) && "preload"].filter(Boolean);
    add(out, "http.hsts", "HSTS", maxAge >= 15552000 ? "ok" : "warn",
      `max-age ${maxAge >= 86400 ? Math.round(maxAge / 86400) + " dní" : maxAge + " s"}${flags.length ? ", " + flags.join(", ") : ""}`,
      maxAge < 15552000 ? "Doporučeno alespoň 180 dní (15552000 s)." : undefined, [hsts]);
  }

  const csp = h.get("content-security-policy");
  const cspRO = h.get("content-security-policy-report-only");
  add(out, "http.csp", "Content-Security-Policy", csp ? "ok" : "warn",
    csp ? "nastaveno" : cspRO ? "jen Report-Only" : "chybí", undefined, [csp ?? cspRO ?? ""].filter(Boolean));

  const xfo = h.get("x-frame-options");
  const frameAnc = csp && /frame-ancestors/i.test(csp);
  add(out, "http.xfo", "Ochrana proti clickjackingu", xfo || frameAnc ? "ok" : "warn",
    xfo ? `X-Frame-Options: ${xfo}` : frameAnc ? "CSP frame-ancestors" : "chybí X-Frame-Options i frame-ancestors");

  const xcto = h.get("x-content-type-options");
  add(out, "http.xcto", "X-Content-Type-Options", xcto?.toLowerCase() === "nosniff" ? "ok" : "warn", xcto ?? "chybí");

  const rp = h.get("referrer-policy");
  add(out, "http.referrer", "Referrer-Policy", rp ? "ok" : "info", rp ?? "chybí (prohlížeč použije strict-origin-when-cross-origin)");

  const pp = h.get("permissions-policy");
  add(out, "http.permissions", "Permissions-Policy", pp ? "ok" : "info", pp ? "nastaveno" : "chybí", undefined, pp ? [pp] : undefined);

  // ---- Cookies -------------------------------------------------------------
  const cookies = typeof (h as Headers & { getSetCookie?: () => string[] }).getSetCookie === "function"
    ? (h as Headers & { getSetCookie: () => string[] }).getSetCookie()
    : (h.get("set-cookie") ? [h.get("set-cookie")!] : []);
  if (cookies.length) {
    const bad = cookies.map((c) => {
      const name = c.split("=")[0].trim();
      const miss = [
        !/;\s*secure/i.test(c) && "Secure",
        !/;\s*httponly/i.test(c) && "HttpOnly",
        !/;\s*samesite/i.test(c) && "SameSite",
      ].filter(Boolean) as string[];
      return { name, miss };
    });
    const problems = bad.filter((b) => b.miss.length);
    add(out, "http.cookies", "Cookies", problems.some((p) => p.miss.includes("Secure")) ? "warn" : problems.length ? "info" : "ok",
      problems.length ? `${problems.length}/${cookies.length} bez některého příznaku` : `${cookies.length}× v pořádku`,
      "HttpOnly nemusí mít cookies, které čte JavaScript (např. souhlas s cookies).",
      bad.map((b) => `${b.name}  ${b.miss.length ? "chybí: " + b.miss.join(", ") : "OK"}`));
  } else {
    add(out, "http.cookies", "Cookies", "info", "úvodní stránka nenastavuje cookies");
  }

  // ---- Information disclosure ---------------------------------------------
  const leaks = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-varnish"]
    .map((k) => [k, h.get(k)] as const)
    .filter(([, v]) => v);
  const versioned = leaks.filter(([k, v]) => /\d+\.\d+/.test(v!) || k === "x-powered-by" || k.startsWith("x-aspnet"));
  add(out, "http.disclosure", "Prozrazení verzí", versioned.length ? "warn" : "ok",
    versioned.length ? versioned.map(([k, v]) => `${k}: ${v}`).join("; ") : leaks.length ? "bez čísel verzí" : "nic",
    undefined, leaks.map(([k, v]) => `${k}: ${v}`));

  // ---- Compression + raw headers ------------------------------------------
  const enc = h.get("content-encoding");
  add(out, "http.compression", "Komprese", "info", enc ?? "neuvedena (může záviset na Accept-Encoding)");

  const all: string[] = [];
  h.forEach((v, k) => all.push(`${k}: ${v}`));
  add(out, "http.headers", "Všechny hlavičky", "info", `${all.length} hlaviček`, undefined, all.sort());

  return out;
}
