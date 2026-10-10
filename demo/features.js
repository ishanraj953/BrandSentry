/*
 * BrandSentra dashboard — analyst features layered on top of app.js.
 *
 *  - Command palette (Ctrl/Cmd+K): pages, brands, recent scans, open alerts and
 *    typed commands (scan / hunt / investigate / allowlist a domain).
 *  - Deep links: #scan=, #hunt=, #intel=, #alert=, #page=.
 *  - Alert drawer: evidence, look-alike diff, related scans/certs/sightings,
 *    notes, assignee, timeline, single-alert STIX, printable HTML report.
 *  - Bulk triage of selected alerts.
 *  - Look-alike diff + Unicode character inspector on scan results.
 *  - Real sparklines (last 24 h) on the dashboard, certs/second on the feed.
 *  - Sortable tables, feed brand filter, optional sound on critical alerts.
 *  - Storage usage, retention purge, installable PWA, weekly HTML report.
 *
 * Everything is computed from local IndexedDB data and the browser engine.
 */
(function () {
  "use strict";
  const A = window.KCW_APP;
  if (!A) return;
  const { esc, ago, fmtTime, scoreColor, setText, db } = A;
  const S = A.settings;
  const $ = (id) => document.getElementById(id);
  const on = (name, fn) => window.addEventListener("kcw:" + name, (e) => fn(e.detail || {}));
  const engine = () => A.engine();

  // ------------------------------------------------------------------ //
  // Levenshtein alignment → visual diff
  // ------------------------------------------------------------------ //
  function alignDiff(a, b) {
    const n = a.length, m = b.length;
    const d = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
    for (let i = 0; i <= n; i++) d[i][0] = i;
    for (let j = 0; j <= m; j++) d[0][j] = j;
    for (let i = 1; i <= n; i++) for (let j = 1; j <= m; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    const ops = [];
    let i = n, j = m;
    while (i > 0 || j > 0) {
      if (i > 0 && j > 0 && d[i][j] === d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)) { ops.push([a[i - 1] === b[j - 1] ? "eq" : "sub", a[i - 1], b[j - 1]]); i--; j--; }
      else if (i > 0 && d[i][j] === d[i - 1][j] + 1) { ops.push(["del", a[i - 1], ""]); i--; }
      else { ops.push(["ins", "", b[j - 1]]); j--; }
    }
    return { ops: ops.reverse(), distance: d[n][m] };
  }
  function renderDiff(suspicious, brand) {
    const { ops, distance } = alignDiff(Array.from(brand), Array.from(suspicious));
    const top = ops.map(([op, x]) => (op === "ins" ? "" : `<span class="df-${op === "sub" ? "del" : op === "del" ? "del" : "eq"}">${esc(x)}</span>`)).join("");
    const bottom = ops.map(([op, , y]) => (op === "del" ? "" : `<span class="df-${op}">${esc(y)}</span>`)).join("");
    return `<div class="diff-row"><span>brand</span><div class="diff">${top}</div></div><div class="diff-row"><span>suspect</span><div class="diff">${bottom}</div></div>
      <div class="diff-legend"><span><span class="df-sub" style="padding:0 4px">a</span> substituted</span><span><span class="df-ins" style="padding:0 4px">a</span> inserted</span><span><span class="df-del" style="padding:0 4px">a</span> removed</span><span style="margin-left:auto">edit distance ${distance}</span></div>`;
  }
  function renderChars(label) {
    const conf = (KCW.data && KCW.data.confusables) || {};
    return `<div class="char-grid">${Array.from(label).map((ch) => {
      const cp = ch.codePointAt(0), script = KCW.scriptOf(ch), skel = conf[ch];
      const cls = skel && skel !== ch ? "warn" : script === "arabic" ? "arab" : "";
      return `<div class="char-cell ${cls}" title="${esc(ch)} U+${cp.toString(16).toUpperCase().padStart(4, "0")} · ${esc(script)}${skel && skel !== ch ? " · looks like " + esc(skel) : ""}"><div class="ch">${esc(ch)}</div><div class="cp">U+${cp.toString(16).toUpperCase().padStart(4, "0")}</div><div class="sc">${esc(script)}${skel && skel !== ch ? " → " + esc(skel) : ""}</div></div>`;
    }).join("")}</div>`;
  }
  function brandLabelFor(result) {
    const sq = (result.domain_squatting || [])[0];
    if (sq) return KCW.parseDomain(sq.target).label;
    const al = (result.brand_alerts || [])[0];
    if (al && al.evidence && al.evidence.protected_domains && al.evidence.protected_domains[0]) return KCW.parseDomain(al.evidence.protected_domains[0]).label;
    const brandName = (result.phishing.matched_brands || [])[0];
    if (brandName) { const b = engine().brands.find((x) => x.name === brandName || x.short_name === brandName); if (b && b.domains[0]) return KCW.parseDomain(b.domains[0]).label; }
    return null;
  }
  on("scan", ({ result }) => {
    const panel = $("scanResult");
    if (!panel || !result) return;
    const parsed = KCW.parseDomain(result.domain);
    const uni = parsed.unicode_label || parsed.label;
    const brand = brandLabelFor(result);
    let html = "";
    if (brand && uni && brand !== uni) html += `<div class="drawer-sec"><h4>Look-alike diff vs protected label</h4>${renderDiff(uni, brand)}</div>`;
    const scripts = Array.from(KCW.scriptsIn(uni || "") || []);
    if (parsed.is_idn || scripts.length > 1 || /[^\x00-\x7f]/.test(uni || "")) html += `<div class="drawer-sec"><h4>Character inspector · ${esc(scripts.join(" + ") || "latin")}</h4>${renderChars(uni)}</div>`;
    if (html) {
      const card = document.createElement("div");
      card.className = "card";
      card.innerHTML = html;
      panel.appendChild(card);
    }
  });

  // ------------------------------------------------------------------ //
  // Command palette
  // ------------------------------------------------------------------ //
  const PAGES = [
    ["dashboard", "Dashboard"], ["certstream", "CertStream Live"], ["scanner", "Domain Scanner"], ["bulk", "Bulk Scanner"], ["squatgen", "Typosquat Hunter"],
    ["threatintel", "Domain Intel"], ["ctlog", "CT Log Explorer"], ["dnslookup", "DNS Lookup"], ["rdap", "RDAP / WHOIS"], ["history", "Scan History"],
    ["brands", "Brand Monitor"], ["alerts", "Alerts"], ["sightings", "Sightings"], ["analytics", "Analytics"], ["notifications", "Notifications"], ["settings", "Settings"],
  ];
  let PAL = { items: [], index: 0, cache: null };
  function openPalette() {
    if ($("app").style.display !== "block") return;
    $("paletteOverlay").classList.add("show");
    const inp = $("paletteInput"); inp.value = ""; inp.focus();
    PAL.cache = null;
    buildPalette("");
  }
  function closePalette() { $("paletteOverlay").classList.remove("show"); }
  async function paletteData() {
    if (PAL.cache) return PAL.cache;
    const [scans, alerts] = await Promise.all([db.all("scans"), db.all("alerts")]);
    PAL.cache = { scans: scans.sort((a, b) => (b.ts > a.ts ? 1 : -1)).slice(0, 40), alerts: alerts.filter((a) => a.status === "open" || a.status === "investigating").slice(0, 40) };
    return PAL.cache;
  }
  const looksLikeDomain = (q) => /^[a-z0-9؀-ۿÀ-ɏЀ-ӿ.-]+\.[a-z؀-ۿ]{2,}$/i.test(q) || /^https?:\/\//i.test(q);
  async function buildPalette(q) {
    q = q.trim();
    const ql = q.toLowerCase();
    const items = [];
    const cmdMatch = q.match(/^(scan|hunt|intel|investigate|allow|allowlist)\s+(.+)$/i);
    const target = cmdMatch ? cmdMatch[2].trim() : q;
    if (cmdMatch || looksLikeDomain(q)) {
      const norm = KCW.normalizeDomain(target) || target;
      const verb = cmdMatch ? cmdMatch[1].toLowerCase() : "";
      const cmds = [
        ["scan", "Scan", "Full engine analysis + live enrichment", () => quickScan(norm), "scanner"],
        ["hunt", "Hunt look-alikes of", "Generate permutations and resolve them", () => quickSquat(KCW.parseDomain(norm).registrable || norm), "squatgen"],
        ["intel", "Investigate", "DNS · crt.sh · RDAP · URLhaus", () => quickIntel(norm), "threatintel"],
        ["allow", "Allowlist", "Suppress alerts for this domain and its subdomains", () => addAllowlistDomain(norm), "settings"],
      ];
      for (const [key, label, sub, run, icon] of cmds) {
        if (verb && !key.startsWith(verb.slice(0, 4)) && !(verb === "investigate" && key === "intel") && !(verb === "allowlist" && key === "allow")) continue;
        items.push({ group: "Commands", title: `${label} ${norm}`, sub, run, icon });
      }
    }
    const brands = engine().brands.filter((b) => !ql || b.name.toLowerCase().includes(ql) || (b.short_name || "").toLowerCase().includes(ql) || b.domains.some((d) => d.includes(ql))).slice(0, ql ? 6 : 0);
    brands.forEach((b) => items.push({ group: "Brands", title: b.name, sub: b.domains[0], icon: "brands", run: () => quickSquat(b.domains[0]) }));
    PAGES.filter(([, t]) => !ql || t.toLowerCase().includes(ql)).slice(0, ql ? 6 : 16).forEach(([id, t]) => items.push({ group: "Pages", title: t, sub: "go to", icon: id, run: () => showPage(id) }));
    if (ql.length >= 2 || !ql) {
      const data = await paletteData();
      data.alerts.filter((a) => !ql || a.domain.includes(ql) || (a.brand_name || "").toLowerCase().includes(ql)).slice(0, 5)
        .forEach((a) => items.push({ group: "Open alerts", title: a.domain, sub: `${a.severity} · ${a.brand_short || a.brand_name}`, icon: "alerts", run: () => openAlert(a.alert_id) }));
      data.scans.filter((s) => !ql || s.domain.includes(ql)).slice(0, 5)
        .forEach((s) => items.push({ group: "Recent scans", title: s.domain, sub: `${Math.round(s.score)} · ${ago(s.ts)}`, icon: "history", run: () => quickScan(s.domain) }));
    }
    const actions = [
      ["Toggle light / dark theme", "theme", () => toggleTheme()],
      ["Replay sample feed", "certstream", () => { showPage("certstream"); replayFeed(); }],
      ["Export alerts as STIX 2.1", "alerts", () => exportAlertsSTIX()],
      ["Weekly HTML report", "analytics", () => exportSummaryReport()],
      ["Backup workspace (JSON)", "settings", () => exportAllData()],
      ["Keyboard shortcuts", "help", () => openHelp()],
    ];
    actions.filter(([t]) => ql && t.toLowerCase().includes(ql)).forEach(([t, icon, run]) => items.push({ group: "Actions", title: t, sub: "", icon, run }));
    PAL.items = items; PAL.index = 0;
    renderPalette();
  }
  function renderPalette() {
    const list = $("paletteList");
    if (!PAL.items.length) { list.innerHTML = '<div class="empty-state" style="padding:26px"><div class="title">No matches</div><div class="sub">Type a domain to scan it, or a brand, page or action</div></div>'; return; }
    let lastGroup = null, html = "";
    PAL.items.forEach((it, i) => {
      if (it.group !== lastGroup) { html += `<div class="palette-group">${esc(it.group)}</div>`; lastGroup = it.group; }
      html += `<div class="palette-item ${i === PAL.index ? "active" : ""}" data-i="${i}" onmousemove="window.__palHover(${i})" onclick="window.__palRun(${i})"><span class="pi-ico" data-icon="${esc(it.icon || "scanner")}"></span><span class="pi-txt">${esc(it.title)}</span><span class="pi-sub">${esc(it.sub || "")}</span></div>`;
    });
    list.innerHTML = html;
    paintIcons(list);
    const act = list.querySelector(".palette-item.active");
    if (act) act.scrollIntoView({ block: "nearest" });
  }
  window.__palHover = (i) => { if (PAL.index !== i) { PAL.index = i; renderPalette(); } };
  window.__palRun = (i) => { const it = PAL.items[i]; if (!it) return; closePalette(); it.run(); };
  let palTimer = null;
  document.addEventListener("DOMContentLoaded", () => {
    const inp = $("paletteInput");
    if (!inp) return;
    inp.addEventListener("input", () => { clearTimeout(palTimer); palTimer = setTimeout(() => buildPalette(inp.value), 60); });
    inp.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); PAL.index = Math.min(PAL.items.length - 1, PAL.index + 1); renderPalette(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); PAL.index = Math.max(0, PAL.index - 1); renderPalette(); }
      else if (e.key === "Enter") { e.preventDefault(); window.__palRun(PAL.index); }
      else if (e.key === "Tab") { e.preventDefault(); const h = PAL.items.findIndex((it) => it.title.startsWith("Hunt")); if (h >= 0) window.__palRun(h); }
      else if (e.key === "Escape") closePalette();
    });
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if ($("paletteOverlay").classList.contains("show")) closePalette(); else openPalette(); return; }
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (e.key === "?" ) { e.preventDefault(); openHelp(); }
    if (e.key === "Escape") { closePalette(); closeDrawer(); closeHelp(); }
  });
  function openHelp() { $("helpOverlay").classList.add("show"); }
  function closeHelp() { $("helpOverlay").classList.remove("show"); }

  // ------------------------------------------------------------------ //
  // Deep links
  // ------------------------------------------------------------------ //
  function parseHash() {
    const h = location.hash.replace(/^#/, "");
    const out = {};
    h.split("&").forEach((kv) => { const [k, v] = kv.split("="); if (k) out[decodeURIComponent(k)] = decodeURIComponent(v || ""); });
    return out;
  }
  let applyingHash = false;
  async function applyHash() {
    const h = parseHash();
    const keys = Object.keys(h);
    if (!keys.length) return;
    if ($("app").style.display !== "block") { $("analystName").value = $("analystName").value || S.analyst || ""; await enterDashboard(); }
    applyingHash = true;
    try {
      if (h.scan) quickScan(h.scan);
      else if (h.hunt) quickSquat(h.hunt);
      else if (h.intel) quickIntel(h.intel);
      else if (h.alert) { showPage("alerts"); openAlert(h.alert); }
      else if (h.page) showPage(h.page);
    } finally { applyingHash = false; }
  }
  on("page", ({ id }) => { if (!applyingHash && id) history.replaceState(null, "", "#page=" + id); });
  window.addEventListener("hashchange", applyHash);

  // ------------------------------------------------------------------ //
  // Alert drawer, notes, bulk triage, per-alert report
  // ------------------------------------------------------------------ //
  let DRAWER_ID = null;
  async function openAlert(id) {
    const a = await db.get("alerts", id);
    if (!a) { toast("Alert not found", "crit"); return; }
    DRAWER_ID = id;
    const [scans, certs, sightings] = await Promise.all([db.all("scans"), db.all("certs"), db.all("sightings")]);
    const reg = (a.evidence && a.evidence.registrable_domain) || KCW.parseDomain(a.domain).registrable;
    const related = {
      scans: scans.filter((s) => s.domain === a.domain || KCW.parseDomain(s.domain).registrable === reg).sort((x, y) => (y.ts > x.ts ? 1 : -1)).slice(0, 5),
      certs: certs.filter((c) => c.domain === a.domain || KCW.parseDomain(c.domain).registrable === reg).slice(-5).reverse(),
      sightings: sightings.filter((s) => s.domain === a.domain || KCW.parseDomain(s.domain).registrable === reg),
    };
    const protectedDomain = (a.evidence && a.evidence.protected_domains && a.evidence.protected_domains[0]) || "";
    const parsed = KCW.parseDomain(a.domain);
    const uni = parsed.unicode_label || parsed.label;
    const brandLabel = protectedDomain ? KCW.parseDomain(protectedDomain).label : "";
    const badge = (s) => (s === "open" ? "high" : s === "investigating" ? "info" : s === "false_positive" ? "clean" : "low");
    const ev = Object.assign({}, a.evidence || {});
    const evRows = Object.entries(ev).filter(([k]) => !["suspicious_domain", "brand"].includes(k)).map(([k, v]) => `<dt>${esc(k.replace(/_/g, " "))}</dt><dd class="wrap">${esc(Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v)}</dd>`).join("");
    setText("drawerKicker", `${a.severity} · ${(a.alert_type || "").replace(/_/g, " ")} · ${a.alert_id}`);
    setText("drawerTitle", a.domain);
    $("drawerBody").innerHTML = `
      <div class="drawer-sec" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <span class="badge ${esc(a.severity)}">${esc(a.severity)}</span><span class="badge ${badge(a.status)}">${esc(a.status.replace("_", " "))}</span>
        <span class="badge info">${esc(a.source || "browser")}</span><span class="card-sub">detected ${esc(fmtTime(a.detected_at))} (${ago(a.detected_at)})</span>
      </div>
      <div class="drawer-sec"><h4>Target</h4><div style="font-size:.85rem"><strong>${esc(a.brand_name)}</strong>${protectedDomain ? ` · protects <code>${esc(protectedDomain)}</code>` : ""}</div><div style="font-size:.78rem;color:var(--text-dim);margin-top:4px">${esc(a.description)}</div></div>
      ${brandLabel && uni && brandLabel !== uni ? `<div class="drawer-sec"><h4>Look-alike diff</h4>${renderDiff(uni, brandLabel)}</div>` : ""}
      ${parsed.is_idn || /[^\x00-\x7f]/.test(uni || "") ? `<div class="drawer-sec"><h4>Character inspector</h4>${renderChars(uni)}</div>` : ""}
      <div class="drawer-sec"><h4>Triage</h4>
        <div class="drawer-actions">
          ${a.status !== "investigating" && a.status !== "resolved" ? `<button class="act-btn" onclick="drawerAction('investigating')">Investigate</button>` : ""}
          ${a.status !== "resolved" ? `<button class="act-btn" onclick="drawerAction('resolved')">Resolve</button>` : ""}
          ${a.status !== "false_positive" ? `<button class="act-btn danger" onclick="drawerAction('false_positive',true)">False positive + allowlist</button>` : ""}
          ${a.status !== "open" ? `<button class="act-btn" onclick="drawerAction('open')">Reopen</button>` : ""}
        </div>
        <div style="display:flex;gap:8px;margin-top:10px;align-items:center;font-size:.75rem;color:var(--text-dim)">Assignee <input class="api-select" id="drawerAssignee" value="${esc(a.assignee || "")}" placeholder="${esc(S.analyst || "analyst")}" style="flex:1" onchange="saveAlertField('assignee',this.value)"></div>
        <textarea class="note-box" id="drawerNotes" placeholder="Analyst notes — saved locally with the alert" onchange="saveAlertField('notes',this.value)" style="margin-top:8px">${esc(a.notes || "")}</textarea>
      </div>
      <div class="drawer-sec"><h4>Investigate</h4><div class="drawer-actions">
        <button class="act-btn" onclick="closeDrawer();quickScan('${esc(a.domain)}')">🔍 Scan</button>
        <button class="act-btn" onclick="closeDrawer();quickIntel('${esc(a.domain)}')">🧠 Intel</button>
        <button class="act-btn" onclick="closeDrawer();quickSquat('${esc(protectedDomain || reg)}')">🧬 Hunt look-alikes</button>
        <button class="act-btn" onclick="copyIOC()">⧉ Copy IOC JSON</button>
        <button class="act-btn" onclick="alertStix()">↧ STIX 2.1</button>
        <button class="act-btn" onclick="alertReport()">📄 Report (HTML)</button>
        <button class="act-btn" onclick="window.print()">🖨 Print</button>
      </div></div>
      <div class="drawer-sec"><h4>Evidence</h4><dl class="kv-grid" style="grid-template-columns:140px 1fr">${evRows || "<dd>—</dd>"}</dl></div>
      ${related.scans.length ? `<div class="drawer-sec"><h4>Related scans</h4>${related.scans.map((s) => `<div style="display:flex;gap:8px;align-items:center;font-size:.75rem;padding:4px 0;border-bottom:1px dashed var(--border)"><span style="font-family:var(--font-mono);flex:1">${esc(s.domain)}</span><span style="font-family:var(--font-mono);font-weight:700;color:${scoreColor(s.score)}">${Math.round(s.score)}</span><span class="badge ${esc(s.level)}">${esc(s.level)}</span><span style="color:var(--text-muted)">${ago(s.ts)}</span></div>`).join("")}</div>` : ""}
      ${related.certs.length ? `<div class="drawer-sec"><h4>Certificates seen in the feed</h4>${related.certs.map((c) => `<div class="cert-card"><div class="cert-cn">${esc(c.domain)}</div><div class="cert-meta">${esc(fmtTime(c.ts))} · score ${Math.round(c.score)} · keywords ${esc((c.keywords || []).join(", "))}</div><div class="cert-issuer">${esc(c.issuer || "unknown issuer")}${c.synthetic ? " · replay sample" : ""}</div></div>`).join("")}</div>` : ""}
      ${related.sightings.length ? `<div class="drawer-sec"><h4>Sightings</h4>${related.sightings.map((s) => `<div style="font-size:.75rem;padding:4px 0"><span style="font-family:var(--font-mono)">${esc(s.domain)}</span> · ${esc(s.status)} · ${esc((s.ips || []).join(", ") || "no IP")} · seen ${s.seen_count}×</div>`).join("")}</div>` : ""}
      <div class="drawer-sec"><h4>Timeline</h4><ul class="timeline"><li><b>detected</b> via ${esc(a.source || "browser")} · ${esc(fmtTime(a.detected_at))}</li>${(a.history || []).map((h) => `<li><b>${esc(h.status.replace("_", " "))}</b> by ${esc(h.by || "analyst")} · ${esc(fmtTime(h.at))}</li>`).join("")}</ul></div>`;
    paintIcons($("drawer"));
    $("drawer").classList.add("open"); $("drawerBackdrop").classList.add("show");
    if (!applyingHash) history.replaceState(null, "", "#alert=" + encodeURIComponent(id));
  }
  function closeDrawer() {
    if (!$("drawer").classList.contains("open")) return;
    $("drawer").classList.remove("open"); $("drawerBackdrop").classList.remove("show"); DRAWER_ID = null;
    if (location.hash.startsWith("#alert=")) history.replaceState(null, "", "#page=alerts");
  }
  async function drawerAction(status, allowlist) {
    if (!DRAWER_ID) return;
    await alertAction(DRAWER_ID, status, allowlist);
    openAlert(DRAWER_ID);
  }
  async function saveAlertField(field, value) {
    if (!DRAWER_ID) return;
    const a = await db.get("alerts", DRAWER_ID);
    if (!a) return;
    a[field] = value.trim(); a.updated_at = new Date().toISOString();
    await db.put("alerts", a);
    toast(field === "notes" ? "Notes saved" : "Assignee saved", "ok");
    A.renderAlerts();
  }
  async function copyIOC() {
    const a = await db.get("alerts", DRAWER_ID);
    const ioc = { type: "domain-name", value: a.domain, registrable: KCW.parseDomain(a.domain).registrable, severity: a.severity, brand: a.brand_name, alert_type: a.alert_type, detected_at: a.detected_at, source: a.source, evidence: a.evidence, tool: "BrandSentra " + KCW.version };
    try { await navigator.clipboard.writeText(JSON.stringify(ioc, null, 2)); toast("IOC copied to clipboard", "ok"); } catch (e) { downloadJSON(ioc, `ioc_${a.domain}.json`); }
  }
  const toStixRecord = (a) => ({ domain: a.domain, risk_score: a.risk_score || 50, risk_level: a.severity, categories: [a.alert_type], first_seen: a.detected_at, last_seen: a.updated_at || a.detected_at, source: a.source || "browser", brand: a.brand_name, alert_type: a.alert_type, description: a.description });
  async function alertStix() { const a = await db.get("alerts", DRAWER_ID); downloadJSON(await A.buildStixBundle([toStixRecord(a)]), `stix_${a.alert_id}.json`); }
  async function alertReport() { const a = await db.get("alerts", DRAWER_ID); A.downloadBlob(new Blob([alertReportHTML(a)], { type: "text/html" }), `report_${a.alert_id}.html`); }

  // bulk triage
  const selectedAlerts = () => Array.from(document.querySelectorAll(".al-sel:checked")).map((c) => c.value);
  function alertSelectionChanged() {
    const sel = selectedAlerts();
    document.querySelectorAll("#alertTable tr[data-alert]").forEach((tr) => tr.classList.toggle("selected", sel.includes(tr.dataset.alert)));
    const bar = $("alertBulkBar");
    if (bar) { bar.classList.toggle("show", sel.length > 0); setText("alertBulkCount", sel.length + " selected"); }
    const all = $("alertSelectAll"); if (all) all.checked = sel.length > 0 && sel.length === document.querySelectorAll(".al-sel").length;
  }
  function toggleAllAlerts(checked) { document.querySelectorAll(".al-sel").forEach((c) => { c.checked = checked; }); alertSelectionChanged(); }
  function clearAlertSelection() { toggleAllAlerts(false); }
  async function bulkAlerts(status, allowlist) {
    const ids = selectedAlerts();
    if (!ids.length) return;
    if (!confirm(`${status.replace("_", " ")}${allowlist ? " + allowlist" : ""} ${ids.length} alert(s)?`)) return;
    for (const id of ids) await alertAction(id, status, allowlist, true);
    toast(`${ids.length} alert(s) → ${status.replace("_", " ")}`, "ok");
    A.renderAlerts(); A.refreshCounts();
  }
  async function bulkAlertsExport() {
    const ids = selectedAlerts();
    const rows = [];
    for (const id of ids) { const a = await db.get("alerts", id); if (a) rows.push(toStixRecord(a)); }
    downloadJSON(await A.buildStixBundle(rows), "brandsentra_stix_selection.json");
  }

  // ------------------------------------------------------------------ //
  // Reports (self-contained HTML)
  // ------------------------------------------------------------------ //
  const REPORT_CSS = "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;color:#111;line-height:1.5}h1{font-size:1.5rem;margin-bottom:0}h2{font-size:1.05rem;border-bottom:2px solid #eee;padding-bottom:4px;margin-top:28px}table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f4f6fa}code{background:#f2f4f8;padding:1px 4px;border-radius:3px}.tag{display:inline-block;padding:2px 8px;border-radius:99px;font-size:.72rem;font-weight:700;text-transform:uppercase;background:#eee}.critical{background:#ffe1e6;color:#b3122f}.high{background:#ffedd5;color:#9a3d00}.medium{background:#fff6cc;color:#7a5a00}.low{background:#e0f7ea;color:#0b6b3a}.muted{color:#666;font-size:.8rem}pre{background:#f7f8fb;padding:10px;border-radius:6px;overflow:auto;font-size:.75rem}";
  const reportHead = (title) => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title><style>${REPORT_CSS}</style></head><body>`;
  const DISCLAIMER = "Findings are automated heuristics from public data (Certificate Transparency, DNS, RDAP) and are candidates for review, not accusations. Verify independently before blocking, reporting or attributing. Provided as is, without warranty; see DISCLAIMER.md in the project repository.";
  const reportFoot = () => `<p class="muted" style="margin-top:40px">Generated ${esc(new Date().toISOString())} by BrandSentra v${esc(KCW.version)} (browser engine) · analyst ${esc(S.analyst || "—")} · TLP:AMBER</p><p class="muted" style="border-top:1px solid #eee;padding-top:10px">${esc(DISCLAIMER)}</p></body></html>`;
  function alertReportHTML(a) {
    const parsed = KCW.parseDomain(a.domain);
    const ev = a.evidence || {};
    return reportHead(`Alert ${a.alert_id} — ${a.domain}`) + `<h1>${esc(a.domain)}</h1><p class="muted">Alert ${esc(a.alert_id)} · <span class="tag ${esc(a.severity)}">${esc(a.severity)}</span> · ${esc((a.alert_type || "").replace(/_/g, " "))} · status ${esc(a.status)}</p>
      <h2>Summary</h2><p>${esc(a.description)}</p><table><tr><th>Targeted brand</th><td>${esc(a.brand_name)}</td></tr><tr><th>Protected domains</th><td>${esc((ev.protected_domains || []).join(", "))}</td></tr><tr><th>Suspicious domain</th><td><code>${esc(a.domain)}</code>${parsed.is_idn ? ` (${esc(parsed.unicode_hostname)})` : ""}</td></tr><tr><th>Registrable domain</th><td>${esc(parsed.registrable)}</td></tr><tr><th>Detected</th><td>${esc(fmtTime(a.detected_at))} via ${esc(a.source || "browser")}</td></tr><tr><th>Assignee</th><td>${esc(a.assignee || "—")}</td></tr></table>
      ${a.notes ? `<h2>Analyst notes</h2><p>${esc(a.notes).replace(/\n/g, "<br>")}</p>` : ""}
      <h2>Evidence</h2><table>${Object.entries(ev).map(([k, v]) => `<tr><th>${esc(k.replace(/_/g, " "))}</th><td>${esc(Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`).join("")}</table>
      <h2>Timeline</h2><table><tr><th>When</th><th>Event</th><th>By</th></tr><tr><td>${esc(fmtTime(a.detected_at))}</td><td>detected</td><td>${esc(a.source || "")}</td></tr>${(a.history || []).map((h) => `<tr><td>${esc(fmtTime(h.at))}</td><td>${esc(h.status.replace("_", " "))}</td><td>${esc(h.by || "")}</td></tr>`).join("")}</table>
      <h2>Suggested next steps (after manual verification)</h2><ul><li>Confirm the finding independently: content, registrant and hosting via RDAP / hosting abuse contacts.</li><li>Submit the domain to Google Safe Browsing, Microsoft SmartScreen and the registrar abuse desk.</li><li>Notify ${esc(a.brand_name)} security / fraud team; block on mail and web gateways.</li><li>Monitor Certificate Transparency for further look-alikes.</li></ul>` + reportFoot();
  }
  async function exportSummaryReport() {
    const [scans, alerts, certs, sightings] = await Promise.all([db.all("scans"), db.all("alerts"), db.all("certs"), db.all("sightings")]);
    const since = Date.now() - 7 * 86400000;
    const rs = scans.filter((s) => new Date(s.ts) >= since), ra = alerts.filter((a) => new Date(a.detected_at) >= since), rc = certs.filter((c) => new Date(c.ts) >= since);
    const byBrand = {}; ra.forEach((a) => { byBrand[a.brand_name] = (byBrand[a.brand_name] || 0) + 1; });
    const bySev = {}; ra.forEach((a) => { bySev[a.severity] = (bySev[a.severity] || 0) + 1; });
    const top = [...rs.map((s) => ({ d: s.domain, score: s.score, src: "scan" })), ...rc.map((c) => ({ d: c.domain, score: c.score, src: "certstream" }))].sort((a, b) => b.score - a.score).slice(0, 15);
    const html = reportHead("BrandSentra weekly summary") + `<h1>Weekly threat summary</h1><p class="muted">${esc(new Date(since).toISOString().slice(0, 10))} → ${esc(new Date().toISOString().slice(0, 10))} · computed locally from ${scans.length} scans, ${alerts.length} alerts, ${certs.length} feed matches</p>
      <h2>Key figures</h2><table><tr><th>Scans</th><td>${rs.length}</td><th>Alerts raised</th><td>${ra.length}</td></tr><tr><th>Feed matches</th><td>${rc.length}</td><th>Live typosquat sightings</th><td>${sightings.length}</td></tr><tr><th>Open alerts</th><td>${alerts.filter((a) => a.status === "open" || a.status === "investigating").length}</td><th>False positives</th><td>${alerts.filter((a) => a.status === "false_positive").length}</td></tr></table>
      <h2>Alerts by severity</h2><table><tr>${["critical", "high", "medium", "low"].map((s) => `<th>${s}</th>`).join("")}</tr><tr>${["critical", "high", "medium", "low"].map((s) => `<td>${bySev[s] || 0}</td>`).join("")}</tr></table>
      <h2>Most targeted brands</h2><table><tr><th>Brand</th><th>Alerts</th></tr>${Object.entries(byBrand).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join("") || "<tr><td colspan=2>none</td></tr>"}</table>
      <h2>Highest-risk domains</h2><table><tr><th>Domain</th><th>Score</th><th>Source</th></tr>${top.map((t) => `<tr><td><code>${esc(t.d)}</code></td><td>${Math.round(t.score)}</td><td>${esc(t.src)}</td></tr>`).join("") || "<tr><td colspan=3>none</td></tr>"}</table>
      <h2>Open alerts</h2><table><tr><th>ID</th><th>Severity</th><th>Brand</th><th>Domain</th><th>Type</th><th>Detected</th><th>Assignee</th></tr>${alerts.filter((a) => a.status === "open" || a.status === "investigating").slice(0, 100).map((a) => `<tr><td>${esc(a.alert_id)}</td><td><span class="tag ${esc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.brand_short || a.brand_name)}</td><td><code>${esc(a.domain)}</code></td><td>${esc((a.alert_type || "").replace(/_/g, " "))}</td><td>${esc(fmtTime(a.detected_at))}</td><td>${esc(a.assignee || "")}</td></tr>`).join("") || "<tr><td colspan=7>none</td></tr>"}</table>` + reportFoot();
    A.downloadBlob(new Blob([html], { type: "text/html" }), `brandsentra_weekly_${new Date().toISOString().slice(0, 10)}.html`);
    toast("Weekly report downloaded", "ok");
  }

  // ------------------------------------------------------------------ //
  // Sparklines
  // ------------------------------------------------------------------ //
  function sparkline(id, series, color) {
    const el = $(id);
    if (!el) return;
    const max = Math.max(...series, 1), n = series.length;
    const pts = series.map((v, i) => `${(i / (n - 1)) * 120},${30 - (v / max) * 26 + 1}`);
    el.innerHTML = `<polygon class="area" points="0,32 ${pts.join(" ")} 120,32" fill="${color}"></polygon><polyline points="${pts.join(" ")}" stroke="${color}"></polyline>`;
  }
  const hourBuckets = (rows, key) => { const out = new Array(24).fill(0); const now = Date.now(); rows.forEach((r) => { const h = Math.floor((now - new Date(r[key]).getTime()) / 3600000); if (h >= 0 && h < 24) out[23 - h]++; }); return out; };
  async function drawDashboardSparks() {
    const [scans, certs, alerts] = await Promise.all([db.all("scans"), db.all("certs"), db.all("alerts")]);
    sparkline("spark-statCerts", hourBuckets(certs, "ts"), "var(--cyan)");
    sparkline("spark-statPhishing", hourBuckets([...scans.filter((s) => s.score >= 50), ...certs.filter((c) => c.score >= 50)].map((r) => ({ t: r.ts })), "t"), "var(--red)");
    sparkline("spark-statAlerts", hourBuckets(alerts, "detected_at"), "var(--orange)");
    sparkline("spark-statDomains", hourBuckets(scans, "ts"), "var(--purple)");
  }
  const RATES = new Array(60).fill(0);
  let lastTotal = 0;
  setInterval(() => { const t = A.feed.stats.total; RATES.push(Math.max(0, t - lastTotal)); lastTotal = t; RATES.shift(); if ($("page-certstream") && $("page-certstream").classList.contains("active")) sparkline("spark-rate", RATES, "var(--green)"); }, 1000);
  on("page", ({ id }) => { if (id === "dashboard") drawDashboardSparks(); if (id === "certstream") sparkline("spark-rate", RATES, "var(--green)"); });
  on("enter", () => { drawDashboardSparks(); fillBrandFilter(); });
  on("alerts", () => { PAL.cache = null; if ($("page-dashboard").classList.contains("active")) drawDashboardSparks(); });

  // ------------------------------------------------------------------ //
  // Feed: brand filter, sound on critical
  // ------------------------------------------------------------------ //
  function fillBrandFilter() {
    const sel = $("feedBrandFilter");
    if (!sel || sel.options.length > 1) return;
    engine().brands.slice().sort((a, b) => a.name.localeCompare(b.name)).forEach((b) => { const o = document.createElement("option"); o.value = b.short_name || b.name; o.textContent = b.short_name || b.name; sel.appendChild(o); });
    const sound = $("feedSound"); if (sound) sound.checked = !!S.soundAlerts;
  }
  let audioCtx = null;
  function beep() {
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = "sine"; o.frequency.setValueAtTime(880, audioCtx.currentTime); o.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);
      g.gain.setValueAtTime(0.0001, audioCtx.currentTime); g.gain.exponentialRampToValueAtTime(0.2, audioCtx.currentTime + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.4);
      o.connect(g).connect(audioCtx.destination); o.start(); o.stop(audioCtx.currentTime + 0.45);
    } catch (e) { /* audio blocked */ }
  }
  function setSound(onOff) { A.saveSetting("soundAlerts", !!onOff); if (onOff) beep(); }
  on("alerts", ({ alerts, source }) => {
    if (S.soundAlerts && source !== "scan" && alerts.some((a) => a.severity === "critical")) beep();
    const first = document.querySelector("#liveFeed .feed-row");
    if (first && alerts.some((a) => a.severity === "critical")) first.classList.add("new-critical");
  });

  // ------------------------------------------------------------------ //
  // Auto-enrichment of new feed alerts (DNS + registration age)
  // ------------------------------------------------------------------ //
  const ENRICH = { queue: [], busy: false, cache: new Map() };
  async function enrichAlert(a) {
    const reg = (a.evidence && a.evidence.registrable_domain) || KCW.parseDomain(a.domain).registrable;
    let info = ENRICH.cache.get(reg);
    if (!info) {
      info = { ips: [], registrar: null, age_days: null, created: null, checked_at: new Date().toISOString() };
      const [dns, rdap] = await Promise.allSettled([A.resolveQuick(a.domain), A.fetchRDAP(reg)]);
      if (dns.status === "fulfilled") { info.ips = dns.value.ips || []; info.resolves = dns.value.resolves; }
      if (rdap.status === "fulfilled") { const rd = A.parseRDAP(rdap.value); info.registrar = rd.registrar; info.age_days = rd.age_days; info.created = rd.created; info.nameservers = rd.nameservers; }
      ENRICH.cache.set(reg, info);
    }
    const fresh = await db.get("alerts", a.alert_id);
    if (!fresh) return;
    fresh.evidence = Object.assign({}, fresh.evidence, { ips: info.ips, resolves: info.resolves, registrar: info.registrar, registered: info.created, age_days: info.age_days, nameservers: info.nameservers, newly_registered: info.age_days !== null && info.age_days < 30 });
    await db.put("alerts", fresh);
    A.emit("alert-updated", { alert: fresh });
    if ($("page-alerts").classList.contains("active")) A.renderAlerts();
  }
  async function pumpEnrich() {
    if (ENRICH.busy) return;
    ENRICH.busy = true;
    try { while (ENRICH.queue.length) { const a = ENRICH.queue.shift(); try { await enrichAlert(a); } catch (e) { /* offline */ } } }
    finally { ENRICH.busy = false; }
  }
  on("alerts", ({ alerts, source }) => {
    if (!S.autoEnrich || source === "replay" || source === "watchtower") return;
    for (const a of alerts) if (!ENRICH.queue.some((q) => q.alert_id === a.alert_id)) ENRICH.queue.push(a);
    if (ENRICH.queue.length > 50) ENRICH.queue.length = 50;
    pumpEnrich();
  });

  // ------------------------------------------------------------------ //
  // Sortable tables (numeric-aware, works on any rendered tbody)
  // ------------------------------------------------------------------ //
  document.addEventListener("click", (e) => {
    const th = e.target.closest("table.sortable th");
    if (!th || th.classList.contains("nosort") || e.target.tagName === "INPUT") return;
    const table = th.closest("table"), tbody = table.querySelector("tbody");
    const idx = Array.from(th.parentNode.children).indexOf(th);
    const asc = !th.classList.contains("sorted-asc");
    table.querySelectorAll("th").forEach((t) => t.classList.remove("sorted-asc", "sorted-desc"));
    th.classList.add(asc ? "sorted-asc" : "sorted-desc");
    const rows = Array.from(tbody.querySelectorAll("tr")).filter((r) => r.children.length > 1);
    const val = (r) => { const c = r.children[idx]; if (!c) return ""; const t = c.textContent.trim(); const n = parseFloat(t.replace(/[^0-9.\-]/g, "")); return t && !isNaN(n) && /^[\-\d.]/.test(t) ? n : t.toLowerCase(); };
    rows.sort((a, b) => { const x = val(a), y = val(b); if (typeof x === "number" && typeof y === "number") return asc ? x - y : y - x; return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x)); });
    rows.forEach((r) => tbody.appendChild(r));
  });

  // ------------------------------------------------------------------ //
  // Bulk list import
  // ------------------------------------------------------------------ //
  async function importBulkFile(file) {
    if (!file) return;
    const text = await file.text();
    const domains = [];
    text.split(/\r?\n/).forEach((line) => {
      line.split(/[,\t;]/).forEach((cell) => { const d = KCW.normalizeDomain(cell.trim().replace(/^"|"$/g, "")); if (d && d.includes(".") && !domains.includes(d)) domains.push(d); });
    });
    if (!domains.length) { toast("No domains found in " + file.name, "crit"); return; }
    const ta = $("bulkInput");
    ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + domains.join("\n");
    updateBulkCount();
    toast(`${domains.length} domain(s) imported from ${file.name}`, "ok");
  }

  // ------------------------------------------------------------------ //
  // Storage, retention, PWA
  // ------------------------------------------------------------------ //
  async function renderStorage() {
    const stores = ["scans", "alerts", "certs", "sightings", "intel"];
    const counts = {};
    for (const s of stores) counts[s] = await db.count(s);
    const el = $("storageCounts");
    if (el) el.innerHTML = stores.map((s) => `<span>${s}: ${counts[s].toLocaleString()}</span>`).join("");
    const rd = $("retentionDays"); if (rd) rd.value = S.retentionDays || 90;
    if (navigator.storage && navigator.storage.estimate) {
      try {
        const est = await navigator.storage.estimate();
        const used = est.usage || 0, quota = est.quota || 0;
        setText("storageUsage", `${(used / 1048576).toFixed(1)} MB used${quota ? " of " + (quota / 1073741824).toFixed(1) + " GB available" : ""}`);
        const fill = $("storageFill"); if (fill) fill.style.width = quota ? Math.max(1, Math.min(100, (100 * used) / quota)).toFixed(2) + "%" : "0%";
      } catch (e) { setText("storageUsage", "usage unavailable"); }
    } else setText("storageUsage", "usage unavailable in this browser");
  }
  async function purgeOldData() {
    const days = S.retentionDays || 90;
    if (!confirm(`Delete scans and feed matches older than ${days} days?`)) return;
    const cutoff = new Date(Date.now() - days * 86400000).toISOString();
    let removed = 0;
    for (const store of ["scans", "certs"]) {
      const rows = await db.all(store);
      for (const r of rows) if ((r.ts || "") < cutoff) { await db.del(store, r.id); removed++; }
    }
    toast(`${removed} record(s) purged`, "ok");
    renderStorage(); A.refreshCounts();
  }
  let installPrompt = null;
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); installPrompt = e; const b = $("installBtn"); if (b) b.style.display = "inline-block"; });
  async function installApp() { if (!installPrompt) return; installPrompt.prompt(); await installPrompt.userChoice; installPrompt = null; const b = $("installBtn"); if (b) b.style.display = "none"; }
  if ("serviceWorker" in navigator && location.protocol !== "file:") {
    window.addEventListener("load", () => { navigator.serviceWorker.register("sw.js").catch(() => { /* static host without SW support */ }); });
  }
  const origSettingsHook = A.PAGE_HOOKS.settings;
  A.PAGE_HOOKS.settings = function () { if (origSettingsHook) origSettingsHook(); renderStorage(); };

  // first-run tip
  on("enter", () => {
    try {
      if (!localStorage.getItem("kcw_tip_seen")) { localStorage.setItem("kcw_tip_seen", "1"); setTimeout(() => toast("Tip: press Ctrl+K to search or run commands, ? for shortcuts"), 1800); }
    } catch (e) { /* ignore */ }
    if (location.hash) applyHash();
  });
  document.addEventListener("DOMContentLoaded", () => { paintIcons(); if (location.hash && !sessionStorage.getItem("kcw_open")) setTimeout(applyHash, 300); });

  Object.assign(window, {
    openPalette, closePalette, openHelp, closeHelp, openAlert, closeDrawer, drawerAction, saveAlertField, copyIOC, alertStix, alertReport,
    alertSelectionChanged, toggleAllAlerts, clearAlertSelection, bulkAlerts, bulkAlertsExport, exportSummaryReport,
    importBulkFile, renderStorage, purgeOldData, installApp, setSound, alignDiff, renderDiff,
  });
})();
