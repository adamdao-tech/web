import { add, type Check, type Status } from "../lib/types";
import { readText, timedFetch, randomLabel } from "../lib/util";
import type { Ctx } from "../ctx";

// Only the *presence* of a file is reported — contents are never returned to the UI.

interface Probe {
  path: string;
  label: string;
  /** status when the validator matches */
  hit: Status;
  test: (body: string, ctype: string) => boolean;
  group: "secret" | "listing" | "panel" | "info";
}

const notHtml = (b: string) => !/<(!doctype|html|head|body)\b/i.test(b.slice(0, 2000));
const envLike = (b: string) => notHtml(b) && /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m.test(b);
const sqlDump = (b: string) => notHtml(b) && /(CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|PostgreSQL database dump)/i.test(b);
const zip = (b: string) => b.startsWith("PK\u0003\u0004");
const phpSource = (b: string) => /<\?php/.test(b) && notHtml(b);

const PROBES: Probe[] = [
  // Version control
  { path: "/.git/HEAD", label: "Git repozitář (.git/HEAD)", hit: "fail", group: "secret", test: (b) => /^ref: refs\/|^[0-9a-f]{40}\s*$/m.test(b) && notHtml(b) },
  { path: "/.git/config", label: "Git konfigurace (.git/config)", hit: "fail", group: "secret", test: (b) => /\[core\]/.test(b) },
  { path: "/.svn/wc.db", label: "SVN repozitář (.svn)", hit: "fail", group: "secret", test: (b) => b.startsWith("SQLite format 3") },
  // Environment / credentials
  { path: "/.env", label: ".env", hit: "fail", group: "secret", test: envLike },
  { path: "/.env.local", label: ".env.local", hit: "fail", group: "secret", test: envLike },
  { path: "/.env.production", label: ".env.production", hit: "fail", group: "secret", test: envLike },
  { path: "/.env.bak", label: ".env.bak", hit: "fail", group: "secret", test: envLike },
  { path: "/.htpasswd", label: ".htpasswd", hit: "fail", group: "secret", test: (b) => notHtml(b) && /^[\w.@-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13})/m.test(b) },
  { path: "/.htaccess", label: ".htaccess", hit: "warn", group: "secret", test: (b) => notHtml(b) && /(RewriteEngine|RewriteRule|Deny from|Require (all|ip)|<IfModule|Options\s)/i.test(b) },
  { path: "/.vscode/sftp.json", label: "VS Code SFTP config", hit: "fail", group: "secret", test: (b) => /"(password|host)"\s*:/.test(b) },
  { path: "/docker-compose.yml", label: "docker-compose.yml", hit: "warn", group: "secret", test: (b) => notHtml(b) && /^services:/m.test(b) },
  // Config backups
  { path: "/wp-config.php.bak", label: "wp-config.php.bak", hit: "fail", group: "secret", test: (b) => /DB_PASSWORD/.test(b) },
  { path: "/wp-config.php~", label: "wp-config.php~", hit: "fail", group: "secret", test: (b) => /DB_PASSWORD/.test(b) },
  { path: "/wp-config.php.save", label: "wp-config.php.save", hit: "fail", group: "secret", test: (b) => /DB_PASSWORD/.test(b) },
  { path: "/wp-config.old", label: "wp-config.old", hit: "fail", group: "secret", test: (b) => /DB_PASSWORD/.test(b) },
  { path: "/configuration.php.bak", label: "Joomla configuration.php.bak", hit: "fail", group: "secret", test: (b) => /JConfig|\$password/.test(b) },
  { path: "/configuration.php~", label: "Joomla configuration.php~", hit: "fail", group: "secret", test: (b) => /JConfig|\$password/.test(b) },
  { path: "/config.php.bak", label: "config.php.bak", hit: "fail", group: "secret", test: phpSource },
  // Dumps / archives
  { path: "/backup.sql", label: "backup.sql", hit: "fail", group: "secret", test: sqlDump },
  { path: "/dump.sql", label: "dump.sql", hit: "fail", group: "secret", test: sqlDump },
  { path: "/database.sql", label: "database.sql", hit: "fail", group: "secret", test: sqlDump },
  { path: "/backup.zip", label: "backup.zip", hit: "fail", group: "secret", test: zip },
  { path: "/www.zip", label: "www.zip", hit: "fail", group: "secret", test: zip },
  // Logs / debug
  { path: "/wp-content/debug.log", label: "WP debug.log", hit: "fail", group: "secret", test: (b) => notHtml(b) && /PHP (Fatal|Warning|Notice|Deprecated)/.test(b) },
  { path: "/error_log", label: "error_log", hit: "warn", group: "secret", test: (b) => notHtml(b) && /(PHP (Fatal|Warning|Notice)|\[error\])/.test(b) },
  { path: "/phpinfo.php", label: "phpinfo.php", hit: "warn", group: "secret", test: (b) => /phpinfo\(\)|<title>PHP \d/.test(b) },
  { path: "/info.php", label: "info.php", hit: "warn", group: "secret", test: (b) => /phpinfo\(\)|<title>PHP \d/.test(b) },
  { path: "/server-status", label: "Apache server-status", hit: "warn", group: "secret", test: (b) => /Apache Server Status/i.test(b) },
  { path: "/.DS_Store", label: ".DS_Store", hit: "warn", group: "secret", test: (b) => b.includes("Bud1") },
  // Directory listing
  { path: "/wp-content/uploads/", label: "Výpis /wp-content/uploads/", hit: "warn", group: "listing", test: (b) => /<title>Index of/i.test(b) },
  { path: "/images/", label: "Výpis /images/", hit: "warn", group: "listing", test: (b) => /<title>Index of/i.test(b) },
  { path: "/uploads/", label: "Výpis /uploads/", hit: "warn", group: "listing", test: (b) => /<title>Index of/i.test(b) },
  { path: "/backup/", label: "Výpis /backup/", hit: "warn", group: "listing", test: (b) => /<title>Index of/i.test(b) },
  // Admin panels
  { path: "/phpmyadmin/", label: "phpMyAdmin", hit: "warn", group: "panel", test: (b) => /phpMyAdmin/i.test(b) },
  { path: "/adminer.php", label: "Adminer", hit: "warn", group: "panel", test: (b) => /Adminer/i.test(b) && /<form/i.test(b) },
  { path: "/wp-login.php", label: "WordPress přihlášení", hit: "info", group: "panel", test: (b) => /user_login|loginform/i.test(b) },
  { path: "/administrator/", label: "Joomla administrace", hit: "info", group: "panel", test: (b) => /com_login|mod-login|Joomla/i.test(b) },
  // Information
  { path: "/wp-json/wp/v2/users", label: "WP výčet uživatelů (REST)", hit: "warn", group: "info", test: (b) => /^\s*\[\s*\{[\s\S]*"slug"/.test(b) },
  { path: "/xmlrpc.php", label: "WP xmlrpc.php", hit: "info", group: "info", test: (b) => /XML-RPC server accepts POST requests only/i.test(b) },
  { path: "/readme.html", label: "WP readme.html (prozrazuje verzi)", hit: "info", group: "info", test: (b) => /WordPress/i.test(b) && /<h1/i.test(b) },
  { path: "/composer.json", label: "composer.json", hit: "info", group: "info", test: (b) => /"require"\s*:/.test(b) },
];

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  }));
  return out;
}

export async function checkExposed(ctx: Ctx): Promise<Check[]> {
  const out: Check[] = [];

  // Find where the site really lives (https / www) so probes don't all hit redirects.
  let origin = `https://${ctx.domain}`;
  try {
    const r = await timedFetch(origin + "/", { redirect: "follow" });
    r.body?.cancel().catch(() => {});
    origin = new URL(r.url || origin).origin;
  } catch {
    origin = `http://${ctx.domain}`;
  }

  // Baseline: how does the server answer a path that surely does not exist?
  const baseline = await fetchBody(`${origin}/${randomLabel()}`);

  const results = await pool(PROBES, 6, async (p) => {
    const r = await fetchBody(origin + p.path);
    let found = r.status === 200 && p.test(r.body, r.ctype);
    // catch-all servers answering 200 with the homepage for everything
    if (found && baseline.status === 200 && Math.abs(r.body.length - baseline.body.length) < 64 && p.group !== "panel") found = false;
    return { p, status: r.status, found };
  });

  const groups: { key: Probe["group"]; id: string; name: string }[] = [
    { key: "secret", id: "exposed.files", name: "Citlivé soubory" },
    { key: "listing", id: "exposed.listing", name: "Výpis adresářů" },
    { key: "panel", id: "exposed.panels", name: "Administrace" },
    { key: "info", id: "exposed.info", name: "Únik informací" },
  ];
  const rank: Record<Status, number> = { fail: 4, warn: 3, info: 2, ok: 1, skip: 0 };

  for (const g of groups) {
    const rows = results.filter((r) => r.p.group === g.key);
    const hits = rows.filter((r) => r.found);
    const worst = hits.reduce<Status>((s, r) => (rank[r.p.hit] > rank[s] ? r.p.hit : s), "ok");
    add(out, g.id, g.name, worst,
      hits.length ? hits.map((h) => h.p.label).join(", ") : "nic nenalezeno",
      g.key === "panel" && hits.length ? "Veřejně dostupná přihlašovací stránka není chyba, phpMyAdmin/Adminer by ale měly být omezené na IP." : undefined,
      rows.map((r) => `${r.found ? "NALEZENO" : "—       "}  ${r.p.path}  (HTTP ${r.status || "×"})`));
  }

  add(out, "exposed.baseline", "Odpověď na neexistující cestu", "info",
    `HTTP ${baseline.status || "×"}`, baseline.status === 200 ? "Server vrací 200 i pro neexistující cesty — nálezy se porovnávají s touto odpovědí." : undefined);
  return out;
}

async function fetchBody(url: string): Promise<{ status: number; body: string; ctype: string }> {
  try {
    const r = await timedFetch(url, { redirect: "manual", headers: { range: "bytes=0-32767" } }, 7000);
    const ok = r.status === 200 || r.status === 206;
    const body = ok ? await readText(r, 32 * 1024) : (r.body?.cancel().catch(() => {}), "");
    return { status: r.status === 206 ? 200 : r.status, body, ctype: r.headers.get("content-type") ?? "" };
  } catch {
    return { status: 0, body: "", ctype: "" };
  }
}
