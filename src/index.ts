import { Dns } from "./lib/doh";
import { normalizeDomain, findZone } from "./lib/util";
import type { Check, ModuleResult } from "./lib/types";
import type { Ctx } from "./ctx";
import { checkDns } from "./checks/dns";
import { checkSsl } from "./checks/ssl";
import { checkHttp } from "./checks/http";
import { checkContent } from "./checks/content";
import { checkExposed } from "./checks/exposed";
import { checkEmail } from "./checks/email";
import { checkReputation } from "./checks/reputation";

interface Env { ASSETS: Fetcher }

// Each module runs in its own request: the free plan allows 50 subrequests per
// invocation, and splitting keeps every module comfortably below that.
const MODULES: Record<string, { title: string; run: (ctx: Ctx, url: URL) => Promise<Check[]> }> = {
  dns: { title: "DNS", run: (c) => checkDns(c) },
  ssl: { title: "SSL/TLS", run: (c) => checkSsl(c) },
  http: { title: "HTTP", run: (c) => checkHttp(c) },
  content: { title: "Obsah a technologie", run: (c) => checkContent(c) },
  exposed: { title: "Exponované soubory", run: (c) => checkExposed(c) },
  email: { title: "E-mail (DNS)", run: (c, u) => checkEmail(c, u.searchParams.get("dkim")?.trim().toLowerCase() || undefined) },
  reputation: { title: "Reputace", run: (c) => checkReputation(c) },
};

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/api/modules") {
      return json(Object.entries(MODULES).map(([id, m]) => ({ id, title: m.title })));
    }

    const m = url.pathname.match(/^\/api\/check\/([a-z]+)$/);
    if (m) {
      const mod = MODULES[m[1]];
      if (!mod) return json({ error: "neznámý modul" }, 404);
      const domain = normalizeDomain(url.searchParams.get("domain") ?? "");
      if (!domain) return json({ error: "neplatná doména" }, 400);

      const dns = new Dns();
      const t0 = Date.now();
      try {
        const zone = await findZone(dns, domain);
        const ctx: Ctx = { domain, zone, base: domain.replace(/^www\./, ""), dns };
        const checks = await mod.run(ctx, url);
        const result: ModuleResult = { module: m[1], title: mod.title, domain, durationMs: Date.now() - t0, checks };
        return json(result);
      } catch (e) {
        const err = e as Error;
        return json({
          module: m[1], title: mod.title, domain, durationMs: Date.now() - t0,
          checks: [{ id: `${m[1]}.error`, name: "Chyba modulu", status: "fail", value: err.message, items: err.stack?.split("\n").slice(0, 6) }],
        } satisfies ModuleResult);
      }
    }

    if (url.pathname.startsWith("/api/")) return json({ error: "not found" }, 404);
    return env.ASSETS.fetch(req);
  },
} satisfies ExportedHandler<Env>;
