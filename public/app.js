(() => {
  const MODULES = [
    ["dns", "DNS"],
    ["ssl", "SSL/TLS"],
    ["http", "HTTP"],
    ["content", "Obsah a technologie"],
    ["exposed", "Exponované soubory"],
    ["email", "E-mail (DNS)"],
    ["reputation", "Reputace"],
  ];
  const LABEL = { ok: "OK", warn: "Varování", fail: "Chyba", info: "Info", skip: "Přeskočeno" };
  const ORDER = ["fail", "warn", "ok", "info", "skip"];

  const $ = (s) => document.querySelector(s);
  const form = $("#form"), input = $("#domain"), dkim = $("#dkim"), origin = $("#origin"), runBtn = $("#run");
  const modulesEl = $("#modules"), matrixEl = $("#matrix"), summaryEl = $("#summary");
  const totalsEl = $("#totals"), targetEl = $("#target"), emptyEl = $("#empty");
  const results = {};
  let runId = 0;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const slug = (s) => s.replace(/[^a-z0-9]+/gi, "-");

  function normalize(v) {
    let s = v.trim();
    if (!s) return "";
    if (!/^[a-z]+:\/\//i.test(s)) s = "http://" + s;
    try { return new URL(s).hostname.replace(/\.$/, "").toLowerCase(); } catch { return ""; }
  }

  $("#onlyIssues").addEventListener("change", (e) => document.body.classList.toggle("only-issues", e.target.checked));

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const d = normalize(input.value);
    if (!d) { input.setCustomValidity("Zadej doménu, např. example.cz"); input.reportValidity(); return; }
    input.setCustomValidity("");
    input.value = d;
    const q = new URLSearchParams({ d });
    if (dkim.value.trim()) q.set("dkim", dkim.value.trim());
    if (origin.value.trim()) q.set("origin", origin.value.trim());
    history.replaceState(null, "", "?" + q);
    run(d, dkim.value.trim(), origin.value.trim());
  });
  input.addEventListener("input", () => input.setCustomValidity(""));

  function run(domain, selector, originIp) {
    const id = ++runId;
    for (const k in results) delete results[k];
    emptyEl.hidden = true;
    summaryEl.hidden = false;
    targetEl.textContent = domain;
    runBtn.disabled = true;
    runBtn.textContent = "Kontroluji…";

    matrixEl.innerHTML = MODULES.map(([m, t]) => `
      <div class="mx-group" id="mx-${m}">
        <a href="#mod-${m}">${esc(t)}</a>
        <div class="mx-cells"><div class="mx-pending"></div></div>
      </div>`).join("");
    modulesEl.innerHTML = MODULES.map(([m, t]) => `
      <section class="module" id="mod-${m}" aria-busy="true">
        <div class="module-head"><h2>${esc(t)}</h2><span class="module-meta"></span><div class="module-counts"></div></div>
        <div class="loading">Probíhá kontrola…</div>
      </section>`).join("");
    renderTotals();

    let pending = MODULES.length;
    for (const [m, title] of MODULES) {
      const q = new URLSearchParams({ domain });
      if (m === "email" && selector) q.set("dkim", selector);
      if (m === "ssl" && originIp) q.set("origin", originIp);
      fetch(`/api/check/${m}?${q}`)
        .then(async (r) => {
          const j = await r.json().catch(() => null);
          if (!r.ok || !j || !Array.isArray(j.checks)) throw new Error(j?.error || `HTTP ${r.status}`);
          return j;
        })
        .then((j) => { if (id === runId) renderModule(m, j); })
        .catch((err) => { if (id === runId) renderModule(m, { title, checks: [{ id: `${m}.err`, name: "Modul selhal", status: "fail", value: err.message }] }); })
        .finally(() => {
          if (id !== runId) return;
          if (--pending === 0) { runBtn.disabled = false; runBtn.textContent = "Zkontrolovat"; }
        });
    }
  }

  function counts(checks) {
    const c = { ok: 0, warn: 0, fail: 0, info: 0, skip: 0 };
    for (const x of checks) c[x.status] = (c[x.status] || 0) + 1;
    return c;
  }

  function countHtml(c, keys) {
    return keys.filter((k) => c[k]).map((k) =>
      `<span class="t s-${k}"><span class="dot"></span><b>${c[k]}</b> ${LABEL[k].toLowerCase()}</span>`).join("");
  }

  function renderTotals() {
    const all = Object.values(results).flatMap((r) => r.checks);
    totalsEl.innerHTML = all.length ? countHtml(counts(all), ["fail", "warn", "ok"]) : "";
  }

  function renderModule(m, res) {
    results[m] = res;
    const sec = $(`#mod-${m}`);
    const c = counts(res.checks);
    sec.removeAttribute("aria-busy");
    sec.querySelector(".module-meta").textContent = res.durationMs != null ? `${(res.durationMs / 1000).toFixed(1)} s` : "";
    sec.querySelector(".module-counts").innerHTML = countHtml(c, ORDER);

    const list = document.createElement("ul");
    list.className = "checks";
    list.innerHTML = res.checks.map((ch, i) => {
      const hasBody = ch.detail || (ch.items && ch.items.length);
      const cid = `chk-${m}-${slug(ch.id)}-${i}`;
      return `<li class="check s-${ch.status}" id="${cid}">
        <button class="check-row" type="button" ${hasBody ? `aria-expanded="false" aria-controls="${cid}-b"` : "disabled"}>
          <span class="bar" aria-hidden="true"></span>
          <span class="check-name">${hasBody ? '<span class="chev" aria-hidden="true">›</span>' : '<span class="chev"></span>'}${esc(ch.name)}</span>
          <span class="check-value">${esc(ch.value ?? "")}</span>
          <span class="badge">${LABEL[ch.status] ?? ch.status}</span>
        </button>
        ${hasBody ? `<div class="check-body" id="${cid}-b">
          ${ch.detail ? `<p class="check-detail">${esc(ch.detail)}</p>` : ""}
          ${ch.items && ch.items.length ? `<pre class="check-items">${esc(ch.items.join("\n"))}</pre>` : ""}
        </div>` : ""}
      </li>`;
    }).join("");
    sec.querySelector(".loading")?.remove();
    sec.querySelector(".checks")?.remove();
    sec.appendChild(list);

    list.addEventListener("click", (e) => {
      const btn = e.target.closest(".check-row");
      if (!btn || btn.disabled) return;
      const li = btn.parentElement;
      const open = !li.hasAttribute("open");
      li.toggleAttribute("open", open);
      btn.setAttribute("aria-expanded", String(open));
    });

    const cells = $(`#mx-${m} .mx-cells`);
    cells.innerHTML = res.checks.map((ch, i) =>
      `<button type="button" class="mx-cell s-${ch.status}" data-target="chk-${m}-${slug(ch.id)}-${i}"
         title="${esc(ch.name)}: ${esc(ch.value ?? "")}" aria-label="${esc(ch.name)} — ${LABEL[ch.status]}"></button>`).join("");
    renderTotals();
  }

  matrixEl.addEventListener("click", (e) => {
    const cell = e.target.closest(".mx-cell");
    if (!cell) return;
    const li = document.getElementById(cell.dataset.target);
    if (!li) return;
    const btn = li.querySelector(".check-row");
    if (btn && !btn.disabled && !li.hasAttribute("open")) btn.click();
    li.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
    li.classList.remove("flash"); void li.offsetWidth; li.classList.add("flash");
  });

  // Deep link: ?d=example.cz[&dkim=sel]
  const params = new URLSearchParams(location.search);
  const d0 = normalize(params.get("d") || "");
  if (params.get("dkim")) dkim.value = params.get("dkim");
  if (params.get("origin")) origin.value = params.get("origin");
  if (d0) { input.value = d0; run(d0, dkim.value.trim(), origin.value.trim()); } else { input.focus(); }
})();
