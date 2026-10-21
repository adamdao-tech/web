# Webcheck

Kontrola domény z Cloudflare Workeru — DNS, SSL/TLS, HTTP hlavičky, obsah a technologie,
exponované soubory, e-mailové DNS záznamy a blacklisty.

## Moduly

| Modul | Co kontroluje |
|---|---|
| **DNS** | A/AAAA/CNAME, www, NS (min. 2), SOA, shoda SOA serialů napříč NS (přímý dotaz přes TCP), lame delegation, DNSSEC (DS/DNSKEY/AD, bogus), CAA (s dědičností), wildcard, HTTPS RR |
| **SSL/TLS** | vlastní TLS handshake: celý řetězec tak, jak ho server posílá (chybějící intermediate, pořadí, expirovaný intermediate), expirace, SAN pokrytí domény i www, vydavatel, klíč a podpis, CAA vs. vydavatel, TLS 1.0–1.3, vyjednaná šifra, OCSP stapling |
| **HTTP** | přesměrování http→https (301/308), www vs. bez www, smyčky, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies (Secure/HttpOnly/SameSite), prozrazené verze, komprese, výpis hlaviček |
| **Obsah** | CMS a technologie (WordPress + porovnání s aktuální verzí, Joomla, Drupal, Shoptet, Upgates…), mixed content, title, description, lang/viewport/canonical, noindex, Open Graph, robots.txt, sitemap, favicon, security.txt, soft 404 |
| **Exponované soubory** | .git, .svn, .env*, .htpasswd, .htaccess, zálohy wp-config/configuration.php, SQL dumpy, zip zálohy, debug.log, phpinfo, server-status, výpis adresářů, phpMyAdmin/Adminer, WP REST výčet uživatelů. Hlásí jen nález, obsah nikdy nevrací. |
| **E-mail (DNS)** | MX (CNAME, IP, null MX), SPF (rekurzivně, počet lookupů, void lookup, +all/?all, ptr), DMARC (policy, pct, rua, autorizace externích rua), DKIM (běžné selektory + vlastní), MTA-STS (včetně policy souboru a pokrytí MX), TLS-RPT, BIMI |
| **Reputace** | IP webu a MX serverů na DNSBL (Spamhaus, SpamCop, PSBL, Mailspike, NiX Spam, s5h, UCEPROTECT), doména na DBL/SURBL/URIBL |

## Omezení

- Workers se nesmí přímo připojit na IP adresy Cloudflare → u domén za Cloudflare proxy
  se certifikát ověří jen přes HTTPS a nameservery Cloudflare se nedotazují přímo.
- Server jen s TLS 1.3 posílá certifikát šifrovaně → řetězec nejde vyčíst.
- Spamhaus, SURBL a URIBL odmítají dotazy z veřejných resolverů → hlásí se jako „nelze ověřit“.
- Každý modul je samostatný požadavek (Free plán: 50 subrequestů na požadavek).

## API

`GET /api/check/{dns|ssl|http|content|exposed|email|reputation}?domain=example.cz[&dkim=selektor]`

## Vývoj

```
npm install
npm run dev        # lokálně na http://localhost:8787
npm run typecheck
npm run deploy
```
