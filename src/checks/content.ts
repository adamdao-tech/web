import { add, type Check } from "../lib/types";
import { readText, timedFetch, randomLabel } from "../lib/util";
import type { Ctx } from "../ctx";

const attr = (tag: string, name: string) =>
  tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"))?.slice(2).find((x) => x !== undefined);

function metaTags(html: string): { name: string; content: string }[] {
  return [...html.matchAll(/<meta\b[^>]*>/gi)].map((m) => ({
    name: (attr(m[0], "name") ?? attr(m[0], "property") ?? attr(m[0], "http-equiv") ?? "").toLowerCase(),
    content: attr(m[0], "content") ?? "",
  })).filter((m) => m.name);
}

interface Tech { name: string; version?: string; evidence: string }

function detectTech(html: string, headers: Headers): Tech[] {
  const t: Tech[] = [];
  const gen = metaTags(html).find((m) => m.name === "generator")?.content ?? "";
  const push = (name: string, evidence: string, version?: string) => {
    if (!t.some((x) => x.name === name)) t.push({ name, version, evidence });
  };

  if (/wordpress/i.test(gen)) push("WordPress", "meta generator", gen.match(/WordPress\s+([\d.]+)/i)?.[1]);
  else if (/\/wp-(content|includes)\//i.test(html)) {
    push("WordPress", "cesty /wp-content/", html.match(/wp-(?:includes|emoji)[^"']*?ver=([\d.]+)/i)?.[1]);
  }
  if (/joomla/i.test(gen)) push("Joomla", "meta generator", gen.match(/Joomla!?\s*([\d.]+)/i)?.[1]);
  else if (/\/media\/(jui|system\/js|templates\/site)\//i.test(html)) push("Joomla", "cesty /media/jui/");
  if (/drupal/i.test(gen) || /drupal-settings-json|Drupal\.settings/i.test(html)) push("Drupal", "drupal-settings", gen.match(/Drupal\s+([\d.]+)/i)?.[1]);
  if (/cdn\.myshoptet\.com|shoptet/i.test(html) && /shoptet/i.test(html)) push("Shoptet", "cdn.myshoptet.com");
  if (/upgates/i.test(html)) push("Upgates", "upgates");
  if (/cdn\.shopify\.com/i.test(html)) push("Shopify", "cdn.shopify.com");
  if (/prestashop/i.test(html) || /prestashop/i.test(gen)) push("PrestaShop", "prestashop");
  if (/static\.wixstatic\.com|wix\.com/i.test(html)) push("Wix", "wixstatic");
  if (/webnode/i.test(gen) || /webnode\.(cz|com)/i.test(html)) push("Webnode", "webnode");
  if (/squarespace/i.test(html)) push("Squarespace", "squarespace");
  if (/\/_next\/static\//.test(html)) push("Next.js", "/_next/static/");
  if (/\/_nuxt\//.test(html)) push("Nuxt", "/_nuxt/");
  if (/elementor/i.test(html)) push("Elementor", "elementor", html.match(/elementor[^"']*?ver=([\d.]+)/i)?.[1]);
  if (/woocommerce/i.test(html)) push("WooCommerce", "woocommerce", html.match(/woocommerce[^"']*?ver=([\d.]+)/i)?.[1]);
  const jq = html.match(/jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js/i)?.[1] ?? html.match(/jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)/i)?.[1];
  if (/jquery/i.test(html)) push("jQuery", "script", jq);
  if (/googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/.test(html)) push("Google Tag Manager", "gtm.js");
  if (/google-analytics\.com|gtag\(/.test(html)) push("Google Analytics", "gtag");
  if (gen && !t.some((x) => gen.toLowerCase().includes(x.name.toLowerCase()))) push(gen, "meta generator");
  const xp = headers.get("x-powered-by");
  if (xp) push(xp, "X-Powered-By");
  return t;
}

async function latestWordPress(): Promise<string | undefined> {
  try {
    const r = await timedFetch("https://api.wordpress.org/core/version-check/1.7/", {}, 5000);
    const j = (await r.json()) as { offers?: { current?: string }[] };
    return j.offers?.[0]?.current;
  } catch {
    return undefined;
  }
}

const cmpVer = (a: string, b: string) => {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
};

export async function checkContent(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];
  const { domain } = ctx;

  let res: Response;
  try {
    res = await timedFetch(`https://${domain}/`, { redirect: "follow" });
  } catch (e) {
    try {
      res = await timedFetch(`http://${domain}/`, { redirect: "follow" });
    } catch {
      add(out, "content.fetch", "Načtení stránky", "fail", (e as Error).message);
      return out;
    }
  }
  const finalUrl = res.url || `https://${domain}/`;
  const origin = new URL(finalUrl).origin;
  const ctype = res.headers.get("content-type") ?? "";
  const html = await readText(res, 1024 * 1024);
  const isHtml = /html/i.test(ctype) || /<html/i.test(html);
  if (!isHtml) {
    add(out, "content.fetch", "Načtení stránky", "warn", `odpověď není HTML (${ctype || "bez content-type"})`);
  }

  // ---- Technologies --------------------------------------------------------
  const tech = detectTech(html, res.headers);
  const wp = tech.find((t) => t.name === "WordPress");
  if (wp?.version) {
    const latest = await latestWordPress();
    if (latest) {
      const behind = cmpVer(wp.version, latest) < 0;
      add(out, "content.wp", "Verze WordPressu", behind ? "warn" : "ok",
        `${wp.version}${behind ? ` (aktuální ${latest})` : " — aktuální"}`,
        behind ? "Starší verze jádra — zkontroluj i pluginy." : undefined);
    }
  }
  add(out, "content.tech", "Technologie", "info",
    tech.length ? tech.map((t) => t.name + (t.version ? " " + t.version : "")).join(", ") : "nerozpoznáno",
    undefined, tech.map((t) => `${t.name}${t.version ? " " + t.version : ""}   (${t.evidence})`));

  // ---- Mixed content ---------------------------------------------------------
  if (finalUrl.startsWith("https://")) {
    const insecure = new Set<string>();
    for (const m of html.matchAll(/<(img|script|link|iframe|source|video|audio|embed|object|form)\b[^>]*>/gi)) {
      const tag = m[0];
      const kind = m[1].toLowerCase();
      if (kind === "link" && !/rel\s*=\s*["']?(stylesheet|icon|preload|manifest)/i.test(tag)) continue;
      const url = attr(tag, kind === "link" ? "href" : kind === "form" ? "action" : kind === "object" ? "data" : "src");
      if (url && /^http:\/\//i.test(url)) insecure.add(`<${kind}> ${url}`);
    }
    add(out, "content.mixed", "Mixed content", insecure.size ? "warn" : "ok",
      insecure.size ? `${insecure.size}× zdroj přes http://` : "nenalezen",
      insecure.size ? "Prohlížeč blokuje skripty/styly přes http a u obrázků hlásí nezabezpečenou stránku." : "Kontroluje se jen HTML úvodní stránky.",
      [...insecure].slice(0, 50));
  }

  // ---- Meta ----------------------------------------------------------------
  const metas = metaTags(html);
  const meta = (n: string) => metas.find((m) => m.name === n)?.content;
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim();
  const desc = meta("description");
  const lang = html.match(/<html\b[^>]*\blang\s*=\s*["']?([\w-]+)/i)?.[1];
  const canonical = [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0]).find((t) => /rel\s*=\s*["']?canonical/i.test(t));
  const canonicalHref = canonical ? attr(canonical, "href") : undefined;
  const robotsMeta = meta("robots");

  add(out, "content.title", "Title", !title ? "warn" : title.length > 70 ? "info" : "ok",
    title ? `${title.slice(0, 90)}${title.length > 90 ? "…" : ""}` : "chybí", title ? `${title.length} znaků` : undefined);
  add(out, "content.description", "Meta description", !desc ? "warn" : "ok",
    desc ? `${desc.length} znaků` : "chybí", undefined, desc ? [desc] : undefined);
  add(out, "content.basics", "Základní meta", "info",
    [lang ? `lang=${lang}` : "bez lang", meta("viewport") ? "viewport ✓" : "bez viewport", canonicalHref ? "canonical ✓" : "bez canonical"].join(", "),
    undefined, [
      `lang       ${lang ?? "-"}`, `viewport   ${meta("viewport") ?? "-"}`,
      `canonical  ${canonicalHref ?? "-"}`, `robots     ${robotsMeta ?? "-"}`, `charset    ${/charset/i.test(html.slice(0, 2048)) ? "ano" : "-"}`,
    ]);
  if (robotsMeta && /noindex/i.test(robotsMeta)) {
    add(out, "content.noindex", "Indexace", "warn", `meta robots: ${robotsMeta}`, "Stránka zakazuje indexaci vyhledávači.");
  }
  const og = metas.filter((m) => m.name.startsWith("og:") || m.name.startsWith("twitter:"));
  add(out, "content.og", "Open Graph", og.some((m) => m.name === "og:image") ? "ok" : "info",
    og.length ? `${og.length} tagů${og.some((m) => m.name === "og:image") ? "" : ", bez og:image"}` : "chybí",
    undefined, og.map((m) => `${m.name} = ${m.content}`));

  // ---- Well-known files ------------------------------------------------------
  const get = async (path: string) => {
    try {
      const r = await timedFetch(origin + path, { redirect: "follow" }, 6000);
      const body = r.ok ? await readText(r, 64 * 1024) : (r.body?.cancel().catch(() => {}), "");
      return { status: r.status, ctype: r.headers.get("content-type") ?? "", body, url: r.url };
    } catch (e) {
      return { status: 0, ctype: "", body: "", url: origin + path, error: (e as Error).message };
    }
  };

  const [robots, secTxt, favicon, notFound] = await Promise.all([
    get("/robots.txt"), get("/.well-known/security.txt"), get("/favicon.ico"), get(`/${randomLabel()}.html`),
  ]);

  const robotsIsText = robots.status === 200 && !/<html/i.test(robots.body);
  if (robotsIsText) {
    const blocksAll = /user-agent:\s*\*[\s\S]*?^disallow:\s*\/\s*$/im.test(robots.body);
    add(out, "content.robots", "robots.txt", blocksAll ? "warn" : "ok",
      blocksAll ? "Disallow: / pro všechny roboty" : "existuje",
      blocksAll ? "Celý web je zakázaný pro indexaci." : undefined,
      robots.body.split(/\r?\n/).slice(0, 40));
  } else {
    add(out, "content.robots", "robots.txt", "info", robots.status ? `HTTP ${robots.status}` : "nedostupné");
  }

  const sitemapUrls = robotsIsText ? [...robots.body.matchAll(/^sitemap:\s*(\S+)/gim)].map((m) => m[1]) : [];
  let sitemapFound: string | undefined;
  for (const path of sitemapUrls.length ? sitemapUrls : ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]) {
    const r = await get(path.startsWith("http") ? new URL(path).pathname + new URL(path).search : path);
    if (r.status === 200 && /<(urlset|sitemapindex)/i.test(r.body)) { sitemapFound = r.url; break; }
  }
  add(out, "content.sitemap", "Sitemap", sitemapFound ? "ok" : "info",
    sitemapFound ?? "nenalezena", sitemapUrls.length ? `V robots.txt: ${sitemapUrls.join(", ")}` : undefined);

  const iconLink = [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => m[0]).find((t) => /rel\s*=\s*["']?[^"'>]*icon/i.test(t));
  const favOk = favicon.status === 200 && !/text\/html/i.test(favicon.ctype);
  add(out, "content.favicon", "Favicon", favOk || iconLink ? "ok" : "info",
    iconLink ? `<link rel=icon> ${attr(iconLink, "href") ?? ""}` : favOk ? "/favicon.ico" : "nenalezen");

  const secOk = secTxt.status === 200 && /contact:/i.test(secTxt.body);
  add(out, "content.securitytxt", "security.txt", secOk ? "ok" : "info",
    secOk ? "existuje" : "chybí", undefined, secOk ? secTxt.body.split(/\r?\n/).slice(0, 20) : undefined);

  add(out, "content.404", "Stránka 404", notFound.status === 404 ? "ok" : notFound.status === 200 ? "warn" : "info",
    notFound.status === 404 ? "vrací 404" : notFound.status === 200 ? "neexistující URL vrací 200 (soft 404)" : `HTTP ${notFound.status || "-"}`,
    notFound.status === 200 ? "Vyhledávače pak indexují chybové stránky jako obsah." : undefined);

  return out;
}
