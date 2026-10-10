/*
 * BrandSentra dashboard application.
 *
 * Runs entirely in the browser: the detection engine (engine.js), a live
 * CertStream WebSocket, DNS-over-HTTPS, crt.sh and RDAP lookups, and local
 * persistence in IndexedDB. Nothing is sent to a BrandSentra server unless
 * a backend API URL is configured in Settings.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtTime = (iso) => (iso ? String(iso).replace("T", " ").slice(0, 19) : "—");
  const ago = (iso) => {
    if (!iso) return "—";
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  };
  const scoreColor = (v) => (v >= 80 ? "var(--red)" : v >= 60 ? "var(--orange)" : v >= 40 ? "var(--yellow)" : v > 0 ? "var(--text-dim)" : "var(--green)");
  const levelOf = (v) => KCW.scoreToLevel(v);
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  const emit = (name, detail) => { try { window.dispatchEvent(new CustomEvent("kcw:" + name, { detail })); } catch (e) { /* ignore */ } };

  // ------------------------------------------------------------------ //
  // IndexedDB
  // ------------------------------------------------------------------ //
  const DB_NAME = "brandsentra", DB_VERSION = 3;
  let _db = null;
  function openDB() {
    return new Promise((resolve, reject) => {
      if (_db) return resolve(_db);
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        const mk = (name, opts, indexes) => {
          let store = db.objectStoreNames.contains(name) ? e.target.transaction.objectStore(name) : db.createObjectStore(name, opts);
          (indexes || []).forEach(([n, k]) => { if (!store.indexNames.contains(n)) store.createIndex(n, k); });
        };
        mk("scans", { keyPath: "id", autoIncrement: true }, [["ts", "ts"], ["domain", "domain"]]);
        mk("alerts", { keyPath: "alert_id" }, [["status", "status"], ["domain", "domain"], ["ts", "detected_at"]]);
        mk("certs", { keyPath: "id", autoIncrement: true }, [["ts", "ts"], ["domain", "domain"]]);
        mk("sightings", { keyPath: "domain" }, [["status", "status"]]);
        mk("intel", { keyPath: "domain" });
        mk("settings", { keyPath: "key" });
      };
      req.onsuccess = () => { _db = req.result; resolve(_db); };
      req.onerror = () => reject(req.error);
    });
  }
  function tx(store, mode, fn) {
    return openDB().then((db) => new Promise((resolve, reject) => {
      const t = db.transaction(store, mode);
      const s = t.objectStore(store);
      let result;
      try { result = fn(s); } catch (e) { reject(e); return; }
      t.oncomplete = () => resolve(result && result.result !== undefined ? result.result : result);
      t.onerror = () => reject(t.error);
    }));
  }
  const dbPut = (store, obj) => tx(store, "readwrite", (s) => s.put(obj));
  const dbAdd = (store, obj) => tx(store, "readwrite", (s) => s.add(obj));
  const dbGet = (store, key) => tx(store, "readonly", (s) => s.get(key));
  const dbDel = (store, key) => tx(store, "readwrite", (s) => s.delete(key));
  const dbAll = (store) => tx(store, "readonly", (s) => s.getAll());
  const dbClear = (store) => tx(store, "readwrite", (s) => s.clear());
  const dbCount = (store) => tx(store, "readonly", (s) => s.count());

  // ------------------------------------------------------------------ //
  // Settings & engine
  // ------------------------------------------------------------------ //
  const KEYWORDS_VERSION = 4;
  const RETIRED_KEYWORDS = ["kwi", "mosal"];
  const DEFAULTS = {
    soundAlerts: false, retentionDays: 90,
    feedSource: "ctlogs", ctLogs: [], keywordsVersion: 0,
    feedDeepMatch: true, autoEnrich: true, rules: [], relayUrl: "", relayWatermark: "",
    watchtowerEnabled: true, watchtowerMinutes: 20, watchtowerBrands: 4, watchtowerPerBrand: 60, lastWatchtower: "",
    keywords: KCW.data.certstream_keywords.slice(),
    allowlist: [],
    customBrands: [],
    feedMinScore: 0,
    feedAlertSeverity: "high",
    notifMinSeverity: "high",
    notifEnabled: false,
    certstreamUrl: "wss://certstream.calidog.io/",
    apiUrl: "",
    analyst: "",
  };
  const S = Object.assign({}, DEFAULTS);
  let engine = null;

  async function loadSettings() {
    const rows = await dbAll("settings");
    for (const r of rows) if (r.key in DEFAULTS) S[r.key] = r.value;
    try { S.analyst = localStorage.getItem("kcw_analyst") || S.analyst; } catch (e) { /* private mode */ }
    if ((S.keywordsVersion || 0) < KEYWORDS_VERSION) {
      const merged = S.keywords.filter((k) => !RETIRED_KEYWORDS.includes(k));
      for (const k of DEFAULTS.keywords) if (!merged.includes(k)) merged.push(k);
      S.keywords = merged;
      await dbPut("settings", { key: "keywords", value: merged });
      await dbPut("settings", { key: "keywordsVersion", value: KEYWORDS_VERSION });
      S.keywordsVersion = KEYWORDS_VERSION;
    }
  }
  async function saveSetting(key, value) {
    S[key] = value;
    await dbPut("settings", { key, value });
    if (key === "allowlist" || key === "customBrands") buildEngine();
    if (key === "keywords") { renderKeywords(); feed.keywords = value; }
  }
  window.saveSetting = saveSetting;

  function customBrandToProfile(b) {
    const domains = b.domains.map((d) => KCW.normalizeDomain(d)).filter(Boolean);
    const primary = new Set();
    for (const d of domains) { const l = KCW.parseDomain(d).label; if (l.length >= 3) primary.add(l); }
    const aliases = new Set();
    for (const k of b.keywords) { if (!k.includes(" ")) { const s = KCW.brandSkeleton(k); if (s.length >= 3 && !primary.has(s)) aliases.add(s); } }
    return {
      name: b.name, short_name: b.short || b.name, domains, keywords: b.keywords.map((k) => k.toLowerCase()),
      arabic_keywords: b.arabic || [], aliases: Array.from(aliases), industry: b.industry || "custom", priority: b.priority || "high",
      primary_labels: Array.from(primary).sort(), alias_labels: Array.from(aliases).sort(),
      phrases: b.keywords.map((k) => k.toLowerCase().split(/\s+/).filter(Boolean)).filter((w) => w.length >= 2),
      arabic_normalized: (b.arabic || []).map((k) => KCW.normalizeArabic(k)),
    };
  }
  function buildEngine() {
    const brands = KCW.data.brands.concat(S.customBrands.map(customBrandToProfile));
    const protectedBrands = KCW.data.protected_brands.concat(S.customBrands.flatMap((b) => b.domains));
    engine = KCW.createEngine({ brands, protectedBrands, allowlist: S.allowlist, dedupeWindowSeconds: 3600 });
    setText("statBrands", brands.length);
    const dl = $("brandList");
    if (dl) dl.innerHTML = engine.monitor.protectedDomains().map((d) => `<option value="${esc(d)}">`).join("");
    return engine;
  }

  // ------------------------------------------------------------------ //
  // Live lookups (browser side)
  // ------------------------------------------------------------------ //
  function proxyUrl(url) {
    if (typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"))) {
      if (location.protocol === "http:" || location.protocol === "https:") {
        if (!url.startsWith(location.origin)) {
          return "/api/v1/proxy?url=" + encodeURIComponent(url);
        }
      }
    }
    return url;
  }
  const DOH = "https://dns.google/resolve";
  async function fetchJSON(url, opts) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), (opts && opts.timeout) || 12000);
    try {
      const target = proxyUrl(url);
      const r = await fetch(target, Object.assign({ cache: "no-store", signal: ctrl.signal }, opts || {}));
      if (!r.ok) { const err = new Error("HTTP " + r.status); err.status = r.status; throw err; }
      return await r.json();
    } finally { clearTimeout(t); }
  }
  const DOH_FALLBACK = "https://cloudflare-dns.com/dns-query";
  async function dohQuery(domain, type) {
    let data;
    try { data = await fetchJSON(`${DOH}?name=${encodeURIComponent(domain)}&type=${type}`, { timeout: 8000 }); }
    catch (e) { data = await fetchJSON(`${DOH_FALLBACK}?name=${encodeURIComponent(domain)}&type=${type}`, { timeout: 8000, headers: { accept: "application/dns-json" } }); }
    return { status: data.Status, answers: (data.Answer || []).map((a) => ({ type: a.type, data: a.data, ttl: a.TTL })) };
  }
  async function dohAll(domain) {
    const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    const out = {};
    const results = await Promise.allSettled(types.map((t) => dohQuery(domain, t)));
    let failed = 0;
    types.forEach((t, i) => { if (results[i].status === "fulfilled") out[t] = results[i].value.answers.filter((a) => a.data); else { out[t] = []; failed++; } });
    if (failed === types.length) throw new Error(results[0].reason && results[0].reason.message || "DNS-over-HTTPS unreachable");
    return out;
  }
  async function resolveQuick(domain) {
    try {
      const r = await dohQuery(domain, "A");
      if (r.status === 3) return { resolves: false, ips: [] };
      const ips = r.answers.filter((a) => a.type === 1).map((a) => a.data);
      if (ips.length) return { resolves: true, ips };
      const r6 = await dohQuery(domain, "AAAA");
      const ips6 = r6.answers.filter((a) => a.type === 28).map((a) => a.data);
      if (ips6.length) return { resolves: true, ips: ips6 };
      return { resolves: r.status === 0 ? false : null, ips: [] };
    } catch (e) { return { resolves: null, ips: [], error: e.message }; }
  }
  async function fetchCrtSh(query) {
    const data = await fetchJSON(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`, { timeout: 20000 });
    return Array.isArray(data) ? data : [];
  }
  async function fetchRDAP(domain) {
    const reg = KCW.parseDomain(domain).registrable || domain;
    return fetchJSON(`https://rdap.org/domain/${encodeURIComponent(reg)}`, { timeout: 12000, headers: { Accept: "application/rdap+json, application/json" } });
  }
  function parseRDAP(rd) {
    const evts = rd.events || [];
    const ev = (n) => (evts.find((e) => e.eventAction === n) || {}).eventDate || null;
    const registrar = (rd.entities || []).find((e) => (e.roles || []).includes("registrar"));
    const vcardFn = (ent) => { try { return (ent.vcardArray[1].find((v) => v[0] === "fn") || [])[3] || null; } catch (e) { return null; } };
    let abuse = null;
    for (const ent of rd.entities || []) for (const sub of ent.entities || []) if ((sub.roles || []).includes("abuse")) { try { abuse = (sub.vcardArray[1].find((v) => v[0] === "email") || [])[3] || abuse; } catch (e) { /* ignore */ } }
    const created = ev("registration");
    return {
      registrar: registrar ? vcardFn(registrar) : null, created, expires: ev("expiration"), changed: ev("last changed"),
      nameservers: (rd.nameservers || []).map((n) => (n.ldhName || n.unicodeName || "").toLowerCase()).filter(Boolean),
      status: rd.status || [], abuse, age_days: created ? Math.floor((Date.now() - new Date(created).getTime()) / 86400000) : null,
      dnssec: !!(rd.secureDNS && rd.secureDNS.delegationSigned),
    };
  }
  async function fetchURLhaus(domain) {
    try {
      const target = proxyUrl("https://urlhaus-api.abuse.ch/v1/host/");
      const r = await fetch(target, { method: "POST", body: new URLSearchParams({ host: domain }), cache: "no-store" });
      if (!r.ok) {
        if (r.status === 401) return { query_status: "auth_required" };
        return { query_status: "error", error: "HTTP " + r.status };
      }
      return await r.json();
    } catch (e) {
      return { query_status: "error", error: e.message };
    }
  }

  // ------------------------------------------------------------------ //
  // Alerts & sightings (persistence + notifications)
  // ------------------------------------------------------------------ //
  const RULE_SCORE = { critical: 95, high: 80, medium: 60, low: 40 };
  const RULE_WEIGHT = { critical: 40, high: 25, medium: 15, low: 5 };
  function compileRules() {
    return (S.rules || []).filter((r) => r && r.enabled !== false && r.pattern).map((r) => {
      try { return Object.assign({}, r, { re: new RegExp(r.pattern, r.flags || "i") }); } catch (e) { return null; }
    }).filter(Boolean);
  }
  function hashId(text) { let h = 2166136261; for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h.toString(16).padStart(8, "0"); }
  function ruleAlerts(host, rules, source) {
    const parsed = KCW.parseDomain(host);
    return rules.filter((r) => r.re.test(host) || (parsed.unicode_hostname && r.re.test(parsed.unicode_hostname))).map((r) => ({
      alert_id: "RL-" + hashId(host + "|" + r.id), brand_name: r.name, brand_short: r.name, alert_type: "custom_rule", severity: r.severity || "medium",
      description: `Detection rule "${r.name}" matched ${host}`, evidence: { rule: r.pattern, rule_id: r.id, suspicious_domain: host, registrable_domain: parsed.registrable, source },
      detected_at: new Date().toISOString(), status: "open", assignee: null, risk_score: RULE_SCORE[r.severity] || 60, domain: host,
    }));
  }
  async function persistBrandAlerts(alerts, source, extra) {
    let stored = 0;
    const kept = [];
    const existing = await dbAll("alerts");
    for (const a of alerts) {
      a.source = source;
      if (extra) a.evidence = Object.assign({}, a.evidence, extra);
      a.status = a.status || "open";
      const reg = (a.evidence && a.evidence.registrable_domain) || KCW.parseDomain(a.domain).registrable;
      const dup = existing.find((e) => e.alert_id !== a.alert_id && e.brand_name === a.brand_name && (e.status === "open" || e.status === "investigating") && ((e.evidence && e.evidence.registrable_domain) || KCW.parseDomain(e.domain).registrable) === reg);
      if (dup) {  // same brand + registrable domain already open: consolidate instead of duplicating
        dup.occurrences = (dup.occurrences || 1) + 1;
        dup.last_seen = a.detected_at;
        dup.evidence = dup.evidence || {};
        const hosts = new Set(dup.evidence.hosts || [dup.domain]);
        hosts.add(a.domain);
        dup.evidence.hosts = Array.from(hosts).slice(0, 20);
        if ((SEV_RANK[a.severity] || 0) > (SEV_RANK[dup.severity] || 0)) dup.severity = a.severity;
        await dbPut("alerts", dup);
        continue;
      }
      await dbPut("alerts", a);
      existing.push(a);
      kept.push(a);
      stored++;
      maybeNotify(a);
    }
    if (stored) { refreshCounts(); if (window.__lastAlertForPreview !== undefined) window.__lastAlertForPreview = kept[kept.length - 1]; emit("alerts", { alerts: kept, source }); }
    return stored;
  }
  function maybeNotify(alert) {
    if (!S.notifEnabled || typeof Notification === "undefined" || Notification.permission !== "granted") return;
    if ((SEV_RANK[alert.severity] || 0) < (SEV_RANK[S.notifMinSeverity] || 3)) return;
    try {
      new Notification(`BrandSentra: ${alert.severity.toUpperCase()} — ${alert.brand_short || alert.brand_name}`, { body: alert.description, tag: alert.alert_id });
    } catch (e) { /* ignore */ }
  }
  async function upsertSighting(domain, brand, technique, ips) {
    const now = new Date().toISOString();
    const existing = await dbGet("sightings", domain);
    const row = existing
      ? Object.assign(existing, { last_seen: now, ips, seen_count: (existing.seen_count || 1) + 1 })
      : { domain, brand, technique, ips, status: "new", first_seen: now, last_seen: now, seen_count: 1 };
    await dbPut("sightings", row);
    return { is_new: !existing, row };
  }

  // ------------------------------------------------------------------ //
  // Navigation
  // ------------------------------------------------------------------ //
  const PAGE_HOOKS = {
    dashboard: renderDashboard, alerts: renderAlerts, sightings: renderSightings, brands: renderBrandTable,
    history: renderHistory, analytics: renderAnalytics, settings: renderSettings, notifications: renderNotifications,
    scanner: renderRecentScans, threatintel: renderIntelTable, bulk: updateBulkCount,
  };

  // ------------------------------------------------------------------ //
  // UI chrome: icons, theme, mobile drawer, shortcuts
  // ------------------------------------------------------------------ //
  const svg = (d, extra) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}${extra || ""}</svg>`;
  const ICONS = {
    shield: '<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect width="32" height="32" rx="8" fill="currentColor"/><circle cx="16" cy="16" r="11.5" fill="none" stroke="#f3efff" stroke-opacity=".35" stroke-width=".6" stroke-dasharray="1 1.4"/><path d="M16 6.5 24 10.2v5.2c0 5-3.4 8.1-8 9.3-4.6-1.2-8-4.3-8-9.3v-5.2z" fill="none" stroke="#f3efff" stroke-width="1.7"/><path d="M12.2 15.8 15 18.6l5-5.8" fill="none" stroke="#f2cb55" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    menu: svg('<path d="M4 7h16M4 12h16M4 17h16"/>'),
    close: svg('<path d="M6 6l12 12M18 6 6 18"/>'),
    sun: svg('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
    moon: svg('<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/>'),
    external: svg('<path d="M14 4h6v6M20 4l-9 9M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>'),
    dashboard: svg('<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/>'),
    certstream: svg('<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 19.1a10 10 0 0 1 0-14.2"/>'),
    scanner: svg('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'),
    bulk: svg('<path d="M9 6h11M9 12h11M9 18h11"/><path d="m3.5 6 1 1 2-2M3.5 12l1 1 2-2M3.5 18l1 1 2-2"/>'),
    squatgen: svg('<path d="M6 3v12"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="6" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>'),
    threatintel: svg('<path d="M12 4a4 4 0 0 0-4 4v1a3 3 0 0 0-2 5 3 3 0 0 0 2 5h1a3 3 0 0 0 3 2 3 3 0 0 0 3-2h1a3 3 0 0 0 2-5 3 3 0 0 0-2-5V8a4 4 0 0 0-4-4z"/><path d="M12 4v17"/>'),
    ctlog: svg('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>'),
    dnslookup: svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
    rdap: svg('<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6 16c.6-1.5 1.7-2 3-2s2.4.5 3 2M14 10h4M14 14h4"/>'),
    history: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    brands: svg('<path d="M3 10 12 4l9 6"/><path d="M5 10v9M9 10v9M15 10v9M19 10v9M3 19h18"/>'),
    alerts: svg('<path d="m12 3 9.5 16.5H2.5z"/><path d="M12 10v4M12 17.5v.5"/>'),
    sightings: svg('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>'),
    analytics: svg('<path d="M4 20h16"/><path d="M6 16v-5M11 16V7M16 16v-3M21 16V4" stroke-width="2.2"/>'),
    notifications: svg('<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 21a2 2 0 0 0 4 0"/>'),
    settings: svg('<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2.5"/><circle cx="9" cy="17" r="2.5"/>'),
    help: svg('<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01"/>'),
  };
  function paintIcons(root) {
    (root || document).querySelectorAll("[data-icon]").forEach((el) => {
      const name = el.dataset.icon === "theme" ? (currentTheme() === "light" ? "moon" : "sun") : el.dataset.icon;
      if (ICONS[name]) el.innerHTML = ICONS[name];
    });
  }
  function currentTheme() { return document.documentElement.dataset.theme === "light" ? "light" : "dark"; }
  function applyTheme(theme, persist) {
    document.documentElement.dataset.theme = theme === "light" ? "light" : "dark";
    if (persist) { try { localStorage.setItem("kcw_theme", theme); } catch (e) { /* ignore */ } }
    document.querySelectorAll('[data-icon="theme"]').forEach((el) => { el.innerHTML = ICONS[theme === "light" ? "moon" : "sun"]; el.title = theme === "light" ? "Switch to dark theme" : "Switch to light theme"; });
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === "light" ? "#f8f5fe" : "#0d0818";
  }
  function toggleTheme() { applyTheme(currentTheme() === "light" ? "dark" : "light", true); }
  function initTheme() {
    let stored = null;
    try { stored = localStorage.getItem("kcw_theme"); } catch (e) { /* ignore */ }
    applyTheme(stored === "light" ? "light" : "dark", false);
  }
  function toggleSidebar(force) {
    const sb = $("sidebar"), bd = $("backdrop");
    if (!sb) return;
    const open = typeof force === "boolean" ? force : !sb.classList.contains("open");
    sb.classList.toggle("open", open);
    if (bd) bd.classList.toggle("show", open);
    document.querySelectorAll(".menu-btn").forEach((b) => { b.innerHTML = ICONS[open ? "close" : "menu"]; b.setAttribute("aria-label", open ? "Close menu" : "Open menu"); });
  }
  function fillLandingStats() {
    const D = window.KCW_DATA || {};
    setText("lsBrands", engine ? engine.brands.length : (D.brands || []).length);
    setText("lsKeywords", S.keywords.length);
    const suf = D.suffixes || {};
    setText("lsSuffixes", Object.values(suf).reduce((n, list) => n + list.length, 0));
    setText("lsVersion", "v" + KCW.version + " · IDN / Arabic aware");
    setText("sbVersion", "v" + KCW.version);
  }
  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    const typing = tag === "input" || tag === "textarea" || tag === "select" || e.target.isContentEditable;
    if (e.key === "Escape") { toggleSidebar(false); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if ($("app").style.display !== "block") return;
    if (e.key === "/") { e.preventDefault(); showPage("scanner"); $("scanInput").focus(); $("scanInput").select(); }
    if (e.key === "g") window._kcwG = Date.now();
    else if (window._kcwG && Date.now() - window._kcwG < 900) {
      const map = { d: "dashboard", f: "certstream", s: "scanner", b: "bulk", h: "squatgen", a: "alerts", i: "threatintel", n: "analytics", t: "settings" };
      if (map[e.key]) showPage(map[e.key]);
      window._kcwG = 0;
    }
  });
  Object.assign(window, { toggleTheme, toggleSidebar, paintIcons });

  function showPage(id, el) {
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
    const page = $("page-" + id);
    if (page) page.classList.add("active");
    (el || document.querySelector(`[data-page="${id}"]`))?.classList.add("active");
    if (PAGE_HOOKS[id]) PAGE_HOOKS[id]();
    emit("page", { id });
    toggleSidebar(false);
    const main = document.querySelector(".main");
    if (main) main.scrollTo({ top: 0, behavior: "smooth" });
  }
  window.showPage = showPage;

  async function enterDashboard() {
    const name = ($("analystName").value || "").trim() || "analyst";
    S.analyst = name;
    try { localStorage.setItem("kcw_analyst", name); sessionStorage.setItem("kcw_open", "1"); } catch (e) { /* ignore */ }
    $("loginPage").style.display = "none";
    $("app").style.display = "block";
    setText("currentUser", name);
    await refreshCounts();
    renderDashboard();
    feed.connect();
    emit("enter", { analyst: name });
  }
  function leaveDashboard() {
    try { sessionStorage.removeItem("kcw_open"); } catch (e) { /* ignore */ }
    feed.stop();
    $("app").style.display = "none";
    $("loginPage").style.display = "flex"; fillLandingStats();
  }
  window.enterDashboard = enterDashboard;
  window.leaveDashboard = leaveDashboard;

  // ------------------------------------------------------------------ //
  // Dashboard & counters
  // ------------------------------------------------------------------ //
  function syncNavBadges() {
    document.querySelectorAll(".nav-badge").forEach((b) => b.setAttribute("data-zero", b.textContent.trim() === "0" ? "1" : "0"));
  }
  async function refreshCounts() {
    const [alerts, scans, sightings, certs] = await Promise.all([dbAll("alerts"), dbCount("scans"), dbAll("sightings"), dbCount("certs")]);
    const open = alerts.filter((a) => a.status === "open" || a.status === "investigating");
    const crit = open.filter((a) => a.severity === "critical").length;
    setText("alertCount", open.length);
    setText("statAlerts", open.length);
    setText("statAlertsSub", `${crit} critical · ${alerts.length} total`);
    setText("statDomains", scans);
    setText("statDomainsSub", `${sightings.length} live typosquats · ${S.allowlist.length} allowlisted`);
    setText("sightingCount", sightings.filter((s) => s.status === "new").length);
    setText("feedCount", certs);
    setText("matchedToday", certs);
    syncNavBadges();
    return { alerts, scans, sightings, certs };
  }
  async function renderDashboard() {
    const [scans, certs, alerts] = await Promise.all([dbAll("scans"), dbAll("certs"), dbAll("alerts")]);
    await refreshCounts();
    const phishing = scans.filter((s) => s.score >= 50).length + certs.filter((c) => c.score >= 50).length;
    setText("statPhishing", phishing);
    setText("statCerts", feed.stats.total.toLocaleString());
    setText("statCertsSub", `${feed.state} · ${certs.length} keyword matches stored`);
    const rows = [
      ...scans.map((s) => ({ domain: s.domain, signal: (s.categories || [])[0] || "scan", score: s.score, level: s.level, ts: s.ts })),
      ...certs.map((c) => ({ domain: c.domain, signal: "ct: " + (c.keywords || []).join(","), score: c.score, level: levelOf(c.score), ts: c.ts })),
    ].filter((r) => r.score >= 40).sort((a, b) => b.score - a.score || (b.ts > a.ts ? 1 : -1)).slice(0, 8);
    $("recentThreats").innerHTML = rows.length
      ? rows.map((r) => `<tr><td style="font-family:var(--font-mono);font-size:.75rem">${esc(r.domain)}</td><td><span class="badge ${esc(r.level)}">${esc(String(r.signal).replace(/_/g, " ").slice(0, 28))}</span></td><td><span style="font-family:var(--font-mono);font-weight:700;color:${scoreColor(r.score)}">${Math.round(r.score)}</span></td><td style="color:var(--text-dim);font-size:.75rem">${ago(r.ts)}</td></tr>`).join("")
      : `<tr><td colspan="4"><div class="empty-state"><div class="ico">🔍</div><div class="title">Nothing risky yet</div><div class="sub">Scan a domain or wait for the live feed</div></div></td></tr>`;
    const cats = {};
    scans.forEach((s) => (s.categories || []).forEach((c) => { cats[c] = (cats[c] || 0) + 1; }));
    alerts.forEach((a) => { cats[a.alert_type] = (cats[a.alert_type] || 0) + 1; });
    const palette = ["var(--red)", "var(--orange)", "var(--yellow)", "var(--cyan)", "var(--purple)", "var(--green)", "var(--text-dim)"];
    const data = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([k, v], i) => ({ label: k.replace(/_/g, " "), val: v, color: palette[i] }));
    renderBarChart("categoryChart", data, 180);
    const hits = Object.entries(feed.stats.keywordHits).sort((a, b) => b[1] - a[1]).slice(0, 12);
    $("keywordHits").innerHTML = hits.length
      ? hits.map(([k, v]) => `<div style="background:var(--bg-deep);padding:12px;border-radius:var(--radius-sm);text-align:center"><div style="font-family:var(--font-mono);font-weight:700;color:var(--cyan)">${v}</div><div style="font-size:.7rem;color:var(--text-dim)">${esc(k)}</div></div>`).join("")
      : `<div style="color:var(--text-muted);font-size:.78rem;padding:8px">No keyword hits yet — the live feed is ${esc(feed.state)}.</div>`;
  }
  function renderBarChart(id, data, maxH) {
    const el = $(id);
    if (!el) return;
    if (!data.length) { el.innerHTML = '<div style="color:var(--text-muted);font-size:.75rem;align-self:center;width:100%;text-align:center">No data yet</div>'; return; }
    const maxVal = Math.max(...data.map((d) => d.val), 1);
    el.innerHTML = data.map((d) => `<div class="chart-bar" style="height:${Math.max((d.val / maxVal) * maxH, 8)}px;background:${d.color}" data-label="${esc(String(d.label).split("\n")[0])}" title="${esc(d.label)}: ${d.val}"></div>`).join("");
  }

  // ------------------------------------------------------------------ //
  // CertStream live feed
  // ------------------------------------------------------------------ //
  const REPLAY_SAMPLE = [
    ["novapay-online-banking.xyz", "www.novapay-online-banking.xyz"], ["*.security-services-portal.com"],
    ["kestrel-rewards-portal.top"], ["halcyon-health-portal.club"], ["brandsentra-login.online"],
    ["novapay-verify-identity.ga"], ["*.shopping-deals.site"], ["meridian-bank-auth.tk"],
    ["apex-cloud-booking.buzz"], ["enterprise-id-renewal.icu"], ["vertex-login.ml"],
    ["novapay-mobile-update.cf"], ["kestrel-mart-secure.tk"], ["halcyon-offer.top"],
    ["n0vapay-support.club"], ["novapay-credit-card-apply.xyz"], ["xn--n0vapay-3lc.com"],
  ];
  const feed = {
    ws: null, state: "idle", keywords: [], running: true, stats: { total: 0, matched: 0, high: 0, keywordHits: {}, lastRates: [], startedAt: null },
    retry: 0, timer: null, rateTimer: null, lastSecondCount: 0, replaying: false,
    setState(state, detail) {
      this.state = state;
      const colors = { live: "var(--green)", connecting: "var(--yellow)", reconnecting: "var(--orange)", offline: "var(--red)", paused: "var(--text-dim)", replay: "var(--purple)", idle: "var(--text-dim)" };
      const dot = $("feedDot");
      if (dot) dot.style.background = colors[state] || "var(--text-dim)";
      const pill = $("feedPill");
      if (pill) { pill.className = "feed-pill state-" + state; pill.style.borderColor = state === "live" ? "var(--green-dim)" : ""; }
      setText("feedStatusText", ((S.feedSource || "ctlogs") === "ctlogs" ? "CT logs: " : "CertStream: ") + state + (detail ? " · " + detail : ""));
      setText("csStatus", state);
      setText("csStatusSub", detail || (state === "live" ? this.keywords.length + " keywords" : "—"));
    },
    connect() {
      this.keywords = S.keywords.map((k) => k.toLowerCase());
      this.rules = compileRules();
      this.deepIndex = [];
      for (const b of engine.brands) for (const bl of b.primary_labels || []) if (bl.length >= 3) this.deepIndex.push({ bl, skel: KCW.brandSkeleton(bl), name: b.short_name || b.name });
      this.stats.deep = this.stats.deep || 0;
      this.stop(false);
      if (!this.stats.startedAt) this.stats.startedAt = Date.now();
      if ((S.feedSource || "ctlogs") === "ctlogs" && window.KCW_CT) { window.KCW_CT.start(this); return; }
      if (typeof WebSocket === "undefined") { this.setState("offline", "WebSocket unsupported"); return; }
      this.setState(this.retry ? "reconnecting" : "connecting", this.retry ? `attempt ${this.retry + 1}` : S.certstreamUrl);
      try { this.ws = new WebSocket(S.certstreamUrl); } catch (e) { this.setState("offline", e.message); return; }
      if (!this.stats.startedAt) this.stats.startedAt = Date.now();
      this.ws.onopen = () => { this.retry = 0; this.setState("live", this.keywords.length + " keywords"); this.startRate(); };
      this.ws.onmessage = (ev) => { try { this.handle(JSON.parse(ev.data)); } catch (e) { /* ignore malformed */ } };
      this.ws.onerror = () => { /* onclose follows */ };
      this.ws.onclose = () => {
        if (this.ws === null) return;
        this.ws = null;
        this.retry += 1;
        if (this.retry > 6) { this.setState("offline", "cannot reach " + S.certstreamUrl + " — use Replay"); return; }
        const delay = Math.min(30000, 2000 * 2 ** (this.retry - 1));
        this.setState("reconnecting", `retry in ${Math.round(delay / 1000)}s`);
        this.timer = setTimeout(() => this.connect(), delay);
      };
    },
    stop(markIdle) {
      clearTimeout(this.timer);
      if (window.KCW_CT) window.KCW_CT.stop();
      if (this.ws) { const w = this.ws; this.ws = null; try { w.close(); } catch (e) { /* ignore */ } }
      if (markIdle !== false) this.setState("idle");
    },
    startRate() {
      clearInterval(this.rateTimer);
      this.rateTimer = setInterval(() => {
        const rate = this.stats.total - this.lastSecondCount;
        this.lastSecondCount = this.stats.total;
        this.stats.lastRates.push(rate);
        if (this.stats.lastRates.length > 10) this.stats.lastRates.shift();
        const avg = this.stats.lastRates.reduce((a, b) => a + b, 0) / this.stats.lastRates.length;
        setText("certsPerSec", avg.toFixed(1));
        setText("csTotalSub", this.stats.total.toLocaleString() + " seen this session");
        setText("statCerts", this.stats.total.toLocaleString());
      }, 1000);
    },
    matchKeywords(domain) {
      const lower = domain.toLowerCase();
      const uni = lower.includes("xn--") ? KCW.toUnicode(lower) : lower;
      const tokens = new Set(lower.split(/[^a-z0-9]+/).filter(Boolean));
      const hits = [];
      const tokenList = Array.from(tokens);
      const edge = (kw) => tokens.has(kw) || tokenList.some((t) => (t.startsWith(kw) || t.endsWith(kw)) && t.length <= kw.length + 8);
      for (const kw of this.keywords) {
        if (kw.length < 3) { if (tokens.has(kw)) hits.push(kw); }
        else if (kw.length <= 4 && /^[a-z0-9-]+$/.test(kw)) { if (edge(kw)) hits.push(kw); }
        else if (lower.includes(kw) || (uni !== lower && uni.includes(kw))) hits.push(kw);
      }
      return hits;
    },
    async handle(msg, synthetic) {
      if (msg.message_type !== "certificate_update") return;
      this.stats.total += 1;
      if (!this.running) return;
      const leaf = (msg.data && msg.data.leaf_cert) || {};
      const domains = leaf.all_domains || [];
      const issuer = leaf.issuer || {};
      const issuerName = issuer.O || issuer.CN || "";
      const seen = new Set();
      for (const raw of domains) {
        const host = KCW.normalizeDomain(raw);
        if (!host || seen.has(host)) continue;
        const hits = this.matchKeywords(host);
        const ruleHits = this.rules && this.rules.length ? this.rules.filter((r) => r.re.test(host)) : [];
        ruleHits.forEach((r) => hits.push("rule:" + r.name));
        if (!hits.length && S.feedDeepMatch) {
          const deep = this.deepMatch(host);
          if (deep.length) { this.stats.deep += 1; deep.forEach((n) => hits.push("≈" + n)); }
        }
        if (!hits.length) continue;
        seen.add(host);
        this.stats.matched += 1;
        hits.forEach((k) => { this.stats.keywordHits[k] = (this.stats.keywordHits[k] || 0) + 1; });
        let verdict;
        try { verdict = engine.detector.analyze(host, { issuer: issuerName, is_wildcard: raw.startsWith("*."), source: "certstream" }); } catch (e) { continue; }
        const score = verdict.risk_score;
        if (score >= 60) this.stats.high += 1;
        const feedSrc = (S.feedSource || "ctlogs") === "ctlogs" ? "ctlogs" : "certstream";
        const row = { domain: host, ts: new Date().toISOString(), score, keywords: hits, issuer: issuerName, source: synthetic ? "replay" : (msg.data.source && msg.data.source.name) || feedSrc, brands: verdict.matched_brands, categories: verdict.categories, synthetic: !!synthetic };
        if (score >= (S.feedMinScore || 0)) { try { await dbAdd("certs", row); } catch (e) { /* quota */ } }
        this.render(row, synthetic);
        const alerts = engine.monitor.checkDomain(host, synthetic ? "replay" : feedSrc, true).concat(ruleAlerts(host, ruleHits, feedSrc));
        const keep = alerts.filter((a) => (SEV_RANK[a.severity] || 0) >= (SEV_RANK[S.feedAlertSeverity] || 3));
        if (keep.length) await persistBrandAlerts(keep, synthetic ? "replay" : feedSrc, { issuer: issuerName, risk_score: score, ct_log: (msg.data.source && msg.data.source.name) || "" });
      }
      setText("matchedToday", (await dbCount("certs")).toLocaleString());
      setText("csHighRisk", this.stats.high);
      setText("feedCount", this.stats.matched);
    },
    deepMatch(host) {
      // Cheap prefilter (label contains / skeleton within edit distance 1 of a brand label), then the real brand monitor.
      const parsed = KCW.parseDomain(host);
      const label = parsed.label || "";
      if (label.length < 3 || parsed.is_ip) return [];
      const skel = KCW.brandSkeleton(parsed.unicode_label || label);
      let candidate = false;
      for (const b of this.deepIndex) {
        if (b.bl.length >= 4 && (skel.includes(b.skel) || label.includes(b.bl))) { candidate = true; break; }
        if (Math.abs(skel.length - b.skel.length) <= 1 && KCW.levenshtein(skel, b.skel, 1) <= 1) { candidate = true; break; }
      }
      if (!candidate) return [];
      try { return engine.monitor.checkDomain(host, "deep", false).map((a) => a.brand_short || a.brand_name); } catch (e) { return []; }
    },
    render(row, synthetic) {
      const el = $("liveFeed");
      if (!el) return;
      emit("cert", { row, synthetic });
      if ($("feedOnlyRisky").checked && row.score < 40) return;
      const bf = $("feedBrandFilter");
      if (bf && bf.value && !(row.brands || []).includes(bf.value)) return;
      if (el.firstElementChild && !el.firstElementChild.classList.contains("feed-row")) el.innerHTML = "";
      const level = levelOf(row.score);
      const div = document.createElement("div");
      div.className = "feed-row";
      div.style.borderLeftColor = row.score >= 60 ? "var(--red)" : row.score >= 40 ? "var(--orange)" : "transparent";
      div.innerHTML = `<span class="feed-time">${esc(row.ts.slice(11, 19))}</span><span class="badge ${level}" style="font-size:.6rem">${synthetic ? "replay" : level}</span><span class="feed-domain" title="${esc(row.issuer)}">${esc(row.domain)}${row.brands.length ? ' <span style="color:var(--purple);font-size:.65rem">→ ' + esc(row.brands.join(", ")) + "</span>" : ""}</span><span class="feed-keywords">${esc(row.keywords.join(", "))}</span><span class="feed-score" style="color:${scoreColor(row.score)}">${Math.round(row.score)}</span>`;
      div.style.cursor = "pointer";
      div.onclick = () => quickScan(row.domain);
      el.insertBefore(div, el.firstChild);
      if (el.children.length > 150) el.removeChild(el.lastChild);
    },
  };
  function toggleFeed() {
    feed.running = !feed.running;
    const btn = $("feedToggle");
    if (feed.running) { btn.textContent = "⏸ Pause"; btn.style.borderColor = "var(--green)"; btn.style.color = "var(--green)"; }
    else { btn.textContent = "▶ Resume"; btn.style.borderColor = "var(--orange)"; btn.style.color = "var(--orange)"; }
  }
  function reconnectFeed() { feed.retry = 0; feed.connect(); }
  async function replayFeed() {
    if (feed.replaying) return;
    feed.replaying = true;
    const btn = $("replayBtn"); btn.disabled = true;
    const prevState = feed.state;
    feed.setState("replay", "synthetic sample — not live data");
    for (const sans of REPLAY_SAMPLE) {
      await feed.handle({ message_type: "certificate_update", data: { source: { name: "replay" }, leaf_cert: { all_domains: sans, issuer: { O: "Let's Encrypt" } } } }, true);
      await new Promise((r) => setTimeout(r, 350));
    }
    feed.replaying = false; btn.disabled = false;
    if (feed.ws) feed.setState("live", feed.keywords.length + " keywords"); else feed.setState(prevState === "replay" ? "offline" : prevState);
    toast("Replay finished — rows marked REPLAY are synthetic", "ok");
  }
  window.toggleFeed = toggleFeed; window.reconnectFeed = reconnectFeed; window.replayFeed = replayFeed;

  // ------------------------------------------------------------------ //
  // Scanner
  // ------------------------------------------------------------------ //
  let apiInfo = null;
  async function checkApi() {
    const base = (S.apiUrl || "").replace(/\/+$/, "");
    apiInfo = null;
    const el = $("apiStatus");
    if (!base) { if (el) el.textContent = "API: not configured — scans run on the local engine"; return; }
    try {
      apiInfo = await fetchJSON(base + "/api/v1/health", { timeout: 4000 });
      if (el) el.textContent = `API: connected (v${apiInfo.version}, monitor ${apiInfo.monitor}) — scans also run server-side`;
    } catch (e) { if (el) el.textContent = "API: unreachable (" + e.message + ") — using the local engine"; }
  }
  window.checkApi = checkApi;

  function quickScan(domain) {
    $("scanInput").value = domain;
    showPage("scanner");
    scanDomain();
  }
  window.quickScan = quickScan;

  async function scanDomain() {
    const input = $("scanInput").value.trim();
    if (!input) { toast("Enter a domain", "crit"); return; }
    const btn = $("scanBtn"); btn.disabled = true; btn.textContent = "Scanning…";
    try {
      const result = engine.scan(input, {}, "scan", true);
      const rules = compileRules();
      const matchedRules = rules.filter((r) => r.re.test(result.domain));
      if (matchedRules.length && !result.allowlisted) {
        const p0 = result.phishing;
        for (const r of matchedRules) { p0.indicators.push({ type: "custom_rule", detail: `Rule "${r.name}" (${r.pattern})`, weight: RULE_WEIGHT[r.severity] || 15 }); p0.risk_score = Math.min(100, p0.risk_score + (RULE_WEIGHT[r.severity] || 15)); }
        p0.risk_level = levelOf(p0.risk_score); p0.is_phishing = p0.risk_score >= 50;
        if (!p0.categories.includes("custom_rule")) p0.categories.push("custom_rule");
        result.brand_alerts = result.brand_alerts.concat(ruleAlerts(result.domain, matchedRules, "scan"));
      }
      const enrich = $("scanEnrich").checked;
      renderScanResult(result, { pending: enrich });
      let live = null;
      if (enrich) {
        live = { dns: null, certs: null, rdap: null, errors: [] };
        const [dnsRes, ctRes, rdapRes] = await Promise.allSettled([dohAll(result.domain), fetchCrtSh(result.domain), fetchRDAP(result.domain)]);
        if (dnsRes.status === "fulfilled") live.dns = dnsRes.value; else live.errors.push("DNS: " + dnsRes.reason.message);
        if (ctRes.status === "fulfilled") live.certs = ctRes.value; else live.errors.push("crt.sh: " + ctRes.reason.message);
        if (rdapRes.status === "fulfilled") live.rdap = parseRDAP(rdapRes.value); else live.errors.push("RDAP: " + (rdapRes.reason.status === 404 ? "not registered / no RDAP" : rdapRes.reason.message));
        const p = result.phishing;
        if (live.rdap && live.rdap.age_days !== null && !result.allowlisted) {
          if (live.rdap.age_days < 30) { p.risk_score = Math.min(100, p.risk_score + 15); p.indicators.push({ type: "newly_registered", detail: `Registered ${live.rdap.age_days} days ago`, weight: 15 }); }
          else if (live.rdap.age_days < 180) { p.risk_score = Math.min(100, p.risk_score + 5); p.indicators.push({ type: "recent_registration", detail: `Registered ${live.rdap.age_days} days ago`, weight: 5 }); }
          else p.indicators.push({ type: "established_domain", detail: `Registered ${Math.floor(live.rdap.age_days / 365)} year(s) ago`, weight: 0 });
          p.risk_level = levelOf(p.risk_score); p.is_phishing = p.risk_score >= 50;
        }
        if (live.dns) {
          const a = live.dns.A.length + live.dns.AAAA.length;
          p.indicators.push(a ? { type: "dns_live", detail: "Resolves to " + live.dns.A.concat(live.dns.AAAA).map((r) => r.data).join(", "), weight: 0 } : { type: "no_dns", detail: "Does not resolve (no A/AAAA record)", weight: 0 });
        }
        if (live.certs) p.indicators.push({ type: "ct_history", detail: `${live.certs.length} certificate(s) logged in CT`, weight: 0 });
        renderScanResult(result, { live });
      }
      const p = result.phishing;
      await dbAdd("scans", { domain: result.domain, ts: new Date().toISOString(), score: p.risk_score, level: p.risk_level, categories: p.categories, brands: p.matched_brands, indicators: p.indicators.length, result });
      if (result.brand_alerts.length) await persistBrandAlerts(result.brand_alerts, "scan", { risk_score: p.risk_score });
      await refreshCounts();
      renderRecentScans();
    } catch (e) { toast("Scan failed: " + e.message, "crit"); console.error(e); }
    finally { btn.disabled = false; btn.textContent = "🔍 Analyze"; }
  }
  window.scanDomain = scanDomain;

  function renderScanResult(result, opts) {
    opts = opts || {};
    const p = result.phishing, panel = $("scanResult"), sc = scoreColor(p.risk_score);
    const parsed = p.parsed || {};
    const section = (title, body) => `<div style="margin-top:16px"><div style="font-size:.75rem;font-weight:600;color:var(--text-dim);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">${title}</div>${body}</div>`;
    let html = `<div class="card" style="border-left:4px solid ${sc}">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;gap:12px;flex-wrap:wrap">
        <div><div style="font-size:.75rem;color:var(--text-dim);margin-bottom:4px">Scan result <span class="mode-badge live">ENGINE v${esc(KCW.version)}</span>${result.allowlisted ? '<span class="mode-badge demo">ALLOWLISTED</span>' : ""}</div>
          <div style="font-family:var(--font-mono);font-size:1.1rem;font-weight:700">${esc(result.domain)}</div>
          ${parsed.is_idn ? `<div style="font-family:var(--font-mono);font-size:.85rem;color:var(--purple)">${esc(parsed.unicode_hostname)}</div>` : ""}
          <div style="font-size:.72rem;color:var(--text-muted);margin-top:4px">registrable <code>${esc(parsed.registrable)}</code> · suffix <code>${esc(parsed.suffix)}</code>${parsed.hosting_platform ? " · hosted on <code>" + esc(parsed.hosting_platform) + "</code>" : ""}</div></div>
        <div class="gauge" style="--val:${Math.max(0, Math.min(100, p.risk_score))};--c:${sc}" title="${Math.round(p.risk_score)}/100 risk score"><div class="gauge-in"><span class="gauge-num">${Math.round(p.risk_score)}</span><span class="gauge-lbl">/ 100</span></div></div>
      </div>
      <div class="risk-meter"><div class="risk-meter-fill" style="width:${p.risk_score}%;background:${sc}"></div></div>
      <div style="display:flex;gap:8px;margin:12px 0;flex-wrap:wrap">
        <span class="badge ${esc(p.risk_level)}" style="font-size:.8rem;padding:5px 14px">${esc(p.risk_level)}</span>
        ${p.is_phishing ? '<span class="badge critical" style="font-size:.8rem;padding:5px 14px">⚠ PHISHING LIKELY</span>' : '<span class="badge clean" style="font-size:.8rem;padding:5px 14px">✓ No strong signal</span>'}
        ${p.matched_brands.map((b) => `<span class="badge high" style="font-size:.75rem">targets ${esc(b)}</span>`).join("")}
      </div>
      ${p.categories.length ? `<div style="margin:8px 0">${p.categories.map((c) => `<span class="badge info" style="margin:2px">${esc(c)}</span>`).join("")}</div>` : ""}
      <div style="font-size:.8rem;color:var(--text-dim);margin-top:6px">${esc(p.explanation)}</div>`;
    if (p.indicators.length) html += section(`Indicators (${p.indicators.length})`, `<ul class="indicator-list">${p.indicators.map((i) => `<li class="${i.weight >= 15 ? "high-weight" : i.weight >= 10 ? "med-weight" : "low-weight"}"><strong>${esc(i.type)}</strong><span class="ind-detail">${esc(i.detail)}</span><span class="ind-w">+${i.weight}</span></li>`).join("")}</ul>`);
    if (result.brand_alerts.length) html += section(`Brand alerts (${result.brand_alerts.length})`, result.brand_alerts.map((a) => `<div style="padding:8px 10px;border-left:3px solid var(--red);background:var(--bg-deep);border-radius:var(--radius-sm);margin-bottom:6px;font-size:.8rem"><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span> <strong>${esc(a.brand_name)}</strong> — ${esc(a.alert_type.replace(/_/g, " "))}<div style="color:var(--text-dim);font-size:.7rem;margin-top:3px">${esc(a.description)}</div></div>`).join(""));
    if (result.domain_squatting.length) html += section("Squatting analysis", result.domain_squatting.map((s) => `<div style="display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:.78rem;flex-wrap:wrap"><span class="badge ${esc(s.risk_level)}">${esc(s.risk_level)}</span><span style="font-family:var(--font-mono)">${esc(s.target)}</span><span style="color:var(--text-dim)">${esc(s.attack_types.join(", "))}</span><span style="margin-left:auto;font-family:var(--font-mono);color:var(--text-muted);font-size:.7rem">similarity ${Math.round(s.similarity * 100)}% · confidence ${Math.round(s.confidence * 100)}%</span></div>`).join(""));
    const live = opts.live;
    if (live) {
      if (live.dns) {
        const lines = Object.entries(live.dns).flatMap(([t, recs]) => recs.map((r) => `<div class="record-line"><span class="record-type">${t}</span><span class="record-val">${esc(r.data)}</span><span class="record-ttl">TTL ${r.ttl}</span></div>`));
        html += section("DNS records (Google DoH)", `<div class="record-list">${lines.join("") || '<div style="color:var(--text-muted);font-size:.7rem">No DNS records — the domain does not resolve</div>'}</div>`);
      }
      if (live.rdap) {
        const rd = live.rdap;
        html += section("Registration (RDAP)", `<dl class="kv-grid"><dt>Registrar</dt><dd class="wrap">${esc(rd.registrar || "—")}</dd><dt>Created</dt><dd>${esc((rd.created || "").slice(0, 10) || "—")}${rd.age_days !== null ? ` <span style="color:${rd.age_days < 30 ? "var(--red)" : "var(--text-dim)"}">(${rd.age_days} days ago)</span>` : ""}</dd><dt>Expires</dt><dd>${esc((rd.expires || "").slice(0, 10) || "—")}</dd><dt>Nameservers</dt><dd>${rd.nameservers.map(esc).join("<br>") || "—"}</dd><dt>Abuse contact</dt><dd class="wrap">${esc(rd.abuse || "—")}</dd><dt>Status</dt><dd class="wrap">${rd.status.map((s) => `<span class="badge info" style="margin:2px">${esc(s)}</span>`).join("") || "—"}</dd></dl>`);
      }
      if (live.certs && live.certs.length) html += section(`Certificate Transparency (${live.certs.length})`, live.certs.slice(0, 5).map((c) => `<div class="cert-card"><div class="cert-cn">${esc(c.common_name || c.name_value || "(no CN)")}</div><div class="cert-meta">Logged ${esc((c.entry_timestamp || "").slice(0, 10))} · valid ${esc((c.not_before || "").slice(0, 10))} → ${esc((c.not_after || "").slice(0, 10))}</div><div class="cert-issuer">${esc(c.issuer_name || "")}</div></div>`).join("") + (live.certs.length > 5 ? `<div style="font-size:.7rem;color:var(--text-muted);margin-top:6px">+${live.certs.length - 5} more in the CT Log Explorer</div>` : ""));
      if (live.errors.length) html += `<div style="margin-top:12px;padding:10px;background:rgba(255,140,0,.08);border:1px solid var(--orange-dim);border-radius:var(--radius-sm);font-size:.7rem;color:var(--orange)">⚠ Partial enrichment: ${live.errors.map(esc).join(" · ")}</div>`;
    }
    if (opts.pending) html += `<div class="scan-progress" style="margin-top:12px"><div class="scan-step running"><span class="step-ico">⏳</span><span>Live enrichment: DNS-over-HTTPS · crt.sh · RDAP</span><span class="step-meta">running…</span></div></div>`;
    html += `<div style="margin-top:16px;padding:12px;background:var(--bg-deep);border-radius:var(--radius-sm);font-size:.85rem"><strong>Recommendation:</strong> ${esc(p.recommendation)}</div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button class="btn-sm" onclick="quickIntel('${esc(result.domain)}')">🧠 Investigate</button><button class="btn-sm" onclick="quickSquat('${esc(parsed.registrable || result.domain)}')">🧬 Hunt look-alikes</button><button class="btn-sm" onclick="addAllowlistDomain('${esc(result.domain)}')">✅ Allowlist</button></div></div>`;
    panel.innerHTML = html;
    panel.classList.add("show");
    emit("scan", { result, opts });
  }
  async function renderRecentScans() {
    const scans = (await dbAll("scans")).sort((a, b) => (b.ts > a.ts ? 1 : -1)).slice(0, 12);
    const tb = $("recentScans");
    tb.innerHTML = scans.length ? scans.map((s) => `<tr class="history-row" onclick="quickScan('${esc(s.domain)}')"><td style="font-family:var(--font-mono);font-size:.75rem">${esc(s.domain)}</td><td><span style="font-family:var(--font-mono);font-weight:700;color:${scoreColor(s.score)}">${Math.round(s.score)}/100</span></td><td><span class="badge ${esc(s.level)}">${esc(s.level)}</span></td><td>${(s.categories || []).map((c) => `<span class="badge info" style="margin:1px 2px;font-size:.6rem">${esc(c)}</span>`).join("") || '<span style="color:var(--green)">—</span>'}</td><td style="color:var(--text-dim);font-size:.75rem">${ago(s.ts)}</td></tr>`).join("")
      : `<tr><td colspan="5"><div class="empty-state"><div class="ico">🔍</div><div class="title">No scans yet</div></div></td></tr>`;
  }

  // ------------------------------------------------------------------ //
  // Bulk
  // ------------------------------------------------------------------ //
  let BULK = [];
  function updateBulkCount() { const n = $("bulkInput").value.split("\n").map((l) => l.trim()).filter(Boolean).length; setText("bulkCount", n + " domain" + (n === 1 ? "" : "s")); }
  function loadBulkSample() { $("bulkInput").value = ["nbk-secure-login.xyz", "kfh-verify.top", "zain-rewards.club", "knetpay.info", "moi-kw-fines.online", "nbк.com", "google.com", "login.nbk.com", "kibana.io", "paci-civilid.com"].join("\n"); updateBulkCount(); }
  function clearBulk() { $("bulkInput").value = ""; updateBulkCount(); }
  async function runBulkScan() {
    const lines = Array.from(new Set($("bulkInput").value.split("\n").map((l) => l.trim().toLowerCase()).filter(Boolean)));
    if (!lines.length) { toast("Enter at least one domain", "crit"); return; }
    const doDns = $("bulkDns").checked, btn = $("bulkBtn"), progress = $("bulkProgress"), tb = $("bulkResults");
    btn.disabled = true; btn.textContent = "Scanning…"; progress.style.display = "block"; tb.innerHTML = ""; BULK = [];
    let done = 0;
    for (const d of lines) {
      progress.innerHTML = `<div class="scan-step running"><span class="step-ico">⏳</span><span>Scanning ${esc(d)}</span><span class="step-meta">${done + 1}/${lines.length}</span></div>`;
      let result;
      try { result = engine.scan(d, {}, "bulk", true); } catch (e) { done++; continue; }
      const p = result.phishing;
      let dns = null;
      if (doDns) dns = await resolveQuick(result.domain);
      BULK.push({ domain: result.domain, score: p.risk_score, level: p.risk_level, categories: p.categories, brands: p.matched_brands, alerts: result.brand_alerts.length, dns: dns ? dns.resolves : null, ips: dns ? dns.ips : [] });
      const dnsCell = dns === null ? '<span style="color:var(--text-muted)">—</span>' : dns.resolves === true ? `<span class="sev-crit" title="${esc(dns.ips.join(", "))}">● LIVE</span>` : dns.resolves === false ? '<span style="color:var(--text-muted)">○ NX</span>' : '<span style="color:var(--orange)">? err</span>';
      tb.insertAdjacentHTML("beforeend", `<tr class="history-row" onclick="quickScan('${esc(result.domain)}')"><td style="font-family:var(--font-mono);font-size:.75rem">${esc(result.domain)}</td><td><span style="font-family:var(--font-mono);font-weight:700;color:${scoreColor(p.risk_score)}">${Math.round(p.risk_score)}</span></td><td><span class="badge ${esc(p.risk_level)}">${esc(p.risk_level)}</span></td><td style="font-size:.72rem">${esc(p.matched_brands.join(", ")) || '<span style="color:var(--text-muted)">—</span>'}</td><td>${p.categories.slice(0, 3).map((c) => `<span class="badge info" style="margin:1px;font-size:.6rem">${esc(c)}</span>`).join("")}</td><td>${dnsCell}</td></tr>`);
      await dbAdd("scans", { domain: result.domain, ts: new Date().toISOString(), score: p.risk_score, level: p.risk_level, categories: p.categories, brands: p.matched_brands, indicators: p.indicators.length, result });
      if (result.brand_alerts.length) await persistBrandAlerts(result.brand_alerts, "bulk", { risk_score: p.risk_score });
      done++;
    }
    progress.innerHTML = `<div class="scan-step done"><span class="step-ico">✓</span><span>Complete</span><span class="step-meta">${done} scanned</span></div>`;
    setTimeout(() => (progress.style.display = "none"), 2500);
    setText("bulkResultCount", `${BULK.length} scanned · ${BULK.filter((r) => r.score >= 60).length} high-risk · ${BULK.filter((r) => r.dns === true).length} resolving`);
    $("bulkExport").disabled = false; btn.disabled = false; btn.textContent = "▶ Scan All";
    await refreshCounts();
    toast(`Scanned ${done} domains`, "ok");
  }
  function exportBulkCSV() { downloadCSV(BULK.map((b) => ({ domain: b.domain, score: b.score, level: b.level, brands: b.brands.join("|"), categories: b.categories.join("|"), alerts: b.alerts, dns: b.dns === true ? "live" : b.dns === false ? "nxdomain" : "unknown", ips: b.ips.join("|") })), "brandsentra_bulk.csv"); }
  Object.assign(window, { updateBulkCount, loadBulkSample, clearBulk, runBulkScan, exportBulkCSV });

  // ------------------------------------------------------------------ //
  // Typosquat hunter & sightings
  // ------------------------------------------------------------------ //
  let SQUATS = [], SQUAT_FILTER = "all";
  function quickSquat(brand) { $("squatInput").value = brand; showPage("squatgen"); runSquatGen(); }
  window.quickSquat = quickSquat;
  async function runSquatGen() {
    const brand = KCW.normalizeDomain($("squatInput").value);
    if (!brand) { toast("Enter a brand domain", "crit"); return; }
    const tlds = $("squatTlds").value.split(",").map((s) => s.trim()).filter(Boolean);
    const limit = Math.max(10, Math.min(3000, parseInt($("squatLimit").value, 10) || 400));
    const perms = engine.analyzer.generatePermutationsDetailed(brand, { tlds: tlds.length ? tlds : undefined, includeCombos: $("squatCombos").checked, includeHomoglyphs: $("squatHomo").checked, maxResults: limit }).filter((p) => !engine.analyzer.isLegitimate(p.domain));
    const btn = $("squatBtn"), progress = $("squatProgress");
    btn.disabled = true; btn.textContent = "Working…"; progress.style.display = "block";
    $("squatStats").style.display = "grid"; $("squatResults").style.display = "block";
    SQUATS = perms.map((p) => Object.assign({ status: "pending", ips: [], unicode: p.label.startsWith("xn--") ? KCW.toUnicode(p.domain) : "" }, p));
    setText("sqsGen", SQUATS.length); setText("sqsReg", 0); setText("sqsAvail", 0); setText("sqsUnk", 0);
    renderSquatList();
    if (!$("squatResolve").checked) {
      SQUATS.forEach((p) => (p.status = "unknown"));
      progress.innerHTML = `<div class="scan-step done"><span class="step-ico">✓</span><span>Generated ${SQUATS.length} permutations (DNS resolution disabled)</span></div>`;
      renderSquatList(); btn.disabled = false; btn.textContent = "Generate & Resolve"; return;
    }
    let reg = 0, avail = 0, unk = 0, newSightings = 0;
    const BATCH = 8;
    for (let i = 0; i < SQUATS.length; i += BATCH) {
      const batch = SQUATS.slice(i, i + BATCH);
      progress.innerHTML = `<div class="scan-step running"><span class="step-ico">⏳</span><span>Resolving via DNS-over-HTTPS</span><span class="step-meta">${i}/${SQUATS.length} · ${reg} registered</span></div>`;
      await Promise.all(batch.map(async (p) => {
        const r = await resolveQuick(p.domain);
        p.ips = r.ips;
        if (r.resolves === true) { p.status = "registered"; reg++; const s = await upsertSighting(p.domain, brand, p.technique, r.ips); if (s.is_new) newSightings++; }
        else if (r.resolves === false) { p.status = "available"; avail++; }
        else { p.status = "unknown"; unk++; }
      }));
      setText("sqsReg", reg); setText("sqsAvail", avail); setText("sqsUnk", unk);
      renderSquatList();
    }
    await saveSetting("lastSquatRun", new Date().toISOString());
    progress.innerHTML = `<div class="scan-step done"><span class="step-ico">✓</span><span>Complete — ${reg} registered (${newSightings} new sightings), ${avail} not resolving, ${unk} unknown</span></div>`;
    setTimeout(() => (progress.style.display = "none"), 6000);
    btn.disabled = false; btn.textContent = "Generate & Resolve";
    await refreshCounts();
    if (reg) toast(`⚠ ${reg} look-alike domain(s) of ${brand} resolve`, "crit"); else toast("No resolving look-alikes found", "ok");
  }
  function filterSquat(f) { SQUAT_FILTER = f; renderSquatList(); }
  function renderSquatList() {
    const rows = SQUAT_FILTER === "all" ? SQUATS : SQUATS.filter((p) => p.status === SQUAT_FILTER);
    $("squatList").innerHTML = rows.slice(0, 1500).map((p) => `<div class="perm-card ${esc(p.status)}" onclick="quickScan('${esc(p.domain)}')" style="cursor:pointer"><span class="perm-domain" title="${esc(p.unicode)}">${esc(p.domain)}${p.unicode ? ` <span style="color:var(--purple)">${esc(p.unicode)}</span>` : ""}</span><span class="perm-type">${esc(p.technique.replace(/_/g, " "))}${p.ips.length ? " · " + esc(p.ips[0]) : ""}</span><span class="perm-status ${esc(p.status)}">${esc(p.status)}</span></div>`).join("") || '<div class="empty-state"><div class="sub">No permutations match the filter</div></div>';
  }
  function exportSquatCSV() { downloadCSV(SQUATS.map((p) => ({ domain: p.domain, unicode: p.unicode, technique: p.technique, tld: p.tld, status: p.status, ips: p.ips.join("|") })), "brandsentra_permutations.csv"); }
  Object.assign(window, { runSquatGen, filterSquat, exportSquatCSV });

  async function renderSightings() {
    const status = $("sgStatusFilter").value;
    let rows = (await dbAll("sightings")).sort((a, b) => (b.first_seen > a.first_seen ? 1 : -1));
    const counts = { new: 0, monitoring: 0 };
    rows.forEach((r) => { if (r.status in counts) counts[r.status]++; });
    setText("sgNew", counts.new); setText("sgMonitoring", counts.monitoring); setText("sgTotal", rows.length);
    setText("sgLastRun", S.lastSquatRun ? fmtTime(S.lastSquatRun).slice(0, 16) : "—");
    if (status) rows = rows.filter((r) => r.status === status);
    const tb = $("sightingTable");
    if (!rows.length) { tb.innerHTML = `<tr><td colspan="8"><div class="empty-state"><div class="ico">🎯</div><div class="title">No sightings yet</div><div class="sub">Run the Typosquat Hunter for a brand</div></div></td></tr>`; return; }
    const badge = (s) => (s === "new" ? "critical" : s === "monitoring" ? "high" : s === "takedown_requested" ? "medium" : s === "benign" ? "clean" : "low");
    const act = (d, st, label) => `<button class="act-btn" onclick="sightingAction('${esc(d)}','${st}')">${label}</button>`;
    tb.innerHTML = rows.map((r) => `<tr><td style="font-family:var(--font-mono);font-size:.75rem;cursor:pointer" onclick="quickScan('${esc(r.domain)}')">${esc(r.domain)}</td><td>${esc(r.brand)}</td><td><span class="badge info" style="font-size:.6rem">${esc((r.technique || "").replace(/_/g, " "))}</span></td><td style="font-family:var(--font-mono);font-size:.7rem">${esc((r.ips || []).join(", ")) || "—"}</td><td style="color:var(--text-dim);font-size:.72rem">${fmtTime(r.first_seen)}</td><td style="font-family:var(--font-mono);font-size:.72rem">${r.seen_count || 1}×</td><td><span class="badge ${badge(r.status)}">${esc(r.status.replace(/_/g, " "))}</span></td><td style="white-space:nowrap">${r.status !== "monitoring" ? act(r.domain, "monitoring", "Monitor") : ""}${r.status !== "takedown_requested" ? act(r.domain, "takedown_requested", "Takedown") : ""}${r.status !== "resolved" ? act(r.domain, "resolved", "Resolved") : ""}${r.status !== "benign" ? act(r.domain, "benign", "Benign") : ""}<button class="act-btn danger" onclick="sightingDelete('${esc(r.domain)}')">✕</button></td></tr>`).join("");
  }
  async function sightingAction(domain, status) { const row = await dbGet("sightings", domain); if (!row) return; row.status = status; row.triaged_by = S.analyst; await dbPut("sightings", row); toast(`${domain} → ${status.replace("_", " ")}`, "ok"); renderSightings(); refreshCounts(); }
  async function sightingDelete(domain) { await dbDel("sightings", domain); renderSightings(); refreshCounts(); }
  async function recheckSightings() {
    const rows = await dbAll("sightings");
    let live = 0;
    for (const r of rows) { const res = await resolveQuick(r.domain); if (res.resolves === true) { live++; r.ips = res.ips; r.last_seen = new Date().toISOString(); r.seen_count = (r.seen_count || 1) + 1; } else if (res.resolves === false) { r.last_checked_nx = new Date().toISOString(); } await dbPut("sightings", r); }
    toast(`Re-resolved ${rows.length} sightings — ${live} still live`, "ok");
    renderSightings();
  }
  async function exportSightingsCSV() { downloadCSV((await dbAll("sightings")).map((r) => ({ domain: r.domain, brand: r.brand, technique: r.technique, ips: (r.ips || []).join("|"), status: r.status, first_seen: r.first_seen, last_seen: r.last_seen, seen_count: r.seen_count })), "brandsentra_sightings.csv"); }
  Object.assign(window, { renderSightings, sightingAction, sightingDelete, recheckSightings, exportSightingsCSV });

  // ------------------------------------------------------------------ //
  // Alerts
  // ------------------------------------------------------------------ //
  async function renderAlerts() {
    const all = (await dbAll("alerts")).sort((a, b) => (b.detected_at > a.detected_at ? 1 : -1));
    const sev = { critical: 0, high: 0, medium: 0 };
    let resolved = 0;
    all.forEach((a) => { if (a.status === "open" || a.status === "investigating") { if (a.severity in sev) sev[a.severity]++; } else resolved++; });
    setText("alertCritical", sev.critical); setText("alertHigh", sev.high); setText("alertMedium", sev.medium); setText("alertResolved", resolved);
    const statuses = ($("alertStatusFilter").value || "").split(",").filter(Boolean);
    const sevFilter = $("alertSeverityFilter").value;
    const rows = all.filter((a) => (!statuses.length || statuses.includes(a.status)) && (!sevFilter || a.severity === sevFilter)).slice(0, 300);
    const tb = $("alertTable");
    if (!rows.length) { tb.innerHTML = `<tr><td colspan="10"><div class="empty-state"><div class="ico">🚨</div><div class="title">No alerts</div><div class="sub">Scan a look-alike domain or let the live feed run</div></div></td></tr>`; return; }
    const badge = (s) => (s === "open" ? "high" : s === "investigating" ? "info" : s === "false_positive" ? "clean" : "low");
    if (window.alertSelectionChanged) setTimeout(alertSelectionChanged, 0);
    tb.innerHTML = rows.map((a) => `<tr data-alert="${esc(a.alert_id)}">
      <td onclick="event.stopPropagation()"><input type="checkbox" class="al-sel" value="${esc(a.alert_id)}" onchange="window.alertSelectionChanged&&alertSelectionChanged()"></td>
      <td style="font-family:var(--font-mono);font-size:.7rem;color:var(--cyan);cursor:pointer" title="Open alert" onclick="openAlert('${esc(a.alert_id)}')">${esc(a.alert_id)}</td>
      <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td style="cursor:pointer" onclick="openAlert('${esc(a.alert_id)}')"><strong>${esc(a.brand_short || a.brand_name)}</strong></td>
      <td style="font-family:var(--font-mono);font-size:.75rem;cursor:pointer" onclick="quickScan('${esc(a.domain)}')">${esc(a.domain)}${a.occurrences > 1 ? ` <span class="badge info" style="font-size:.55rem" title="${esc((a.evidence && a.evidence.hosts || []).join(", "))}">×${a.occurrences}</span>` : ""}${a.evidence && a.evidence.newly_registered ? ' <span class="badge critical" style="font-size:.55rem" title="registered less than 30 days ago">new</span>' : ""}${a.evidence && a.evidence.ips && a.evidence.ips.length ? `<div style="font-size:.62rem;color:var(--text-muted)">${esc(a.evidence.ips[0])}</div>` : ""}</td>
      <td>${esc((a.alert_type || "").replace(/_/g, " "))}</td>
      <td style="font-size:.7rem;color:var(--text-dim)">${esc(a.source || "")}</td>
      <td style="color:var(--text-dim);font-size:.72rem">${ago(a.detected_at)}</td>
      <td><span class="badge ${badge(a.status)}">${esc(a.status.replace("_", " "))}</span>${a.assignee ? `<div style="font-size:.62rem;color:var(--text-muted)">${esc(a.assignee)}</div>` : ""}</td>
      <td style="white-space:nowrap">
        ${a.status === "open" ? `<button class="act-btn" onclick="alertAction('${esc(a.alert_id)}','investigating')">Investigate</button>` : ""}
        ${a.status === "open" || a.status === "investigating" ? `<button class="act-btn" onclick="alertAction('${esc(a.alert_id)}','resolved')">Resolve</button><button class="act-btn danger" onclick="alertAction('${esc(a.alert_id)}','false_positive',true)">FP + allowlist</button>` : `<button class="act-btn" onclick="alertAction('${esc(a.alert_id)}','open')">Reopen</button>`}
      </td></tr>`).join("");
  }
  async function alertAction(id, status, allowlist, quiet) {
    const a = await dbGet("alerts", id);
    if (!a) return;
    if (allowlist && !quiet && !confirm(`Mark as false positive and allowlist ${a.domain} (and its subdomains)?`)) return;
    a.status = status; a.assignee = a.assignee || S.analyst; a.updated_at = new Date().toISOString();
    a.history = (a.history || []).concat([{ at: a.updated_at, by: S.analyst, status }]);
    await dbPut("alerts", a);
    if (allowlist) await addAllowlistDomain(a.domain, true);
    if (!quiet) toast(`${id} → ${status.replace("_", " ")}`, "ok");
    emit("alert-updated", { alert: a });
    if (!quiet) { renderAlerts(); refreshCounts(); }
  }
  async function exportAlertsCSV() {
    const rows = (await dbAll("alerts")).map((a) => ({ alert_id: a.alert_id, detected_at: a.detected_at, severity: a.severity, status: a.status, alert_type: a.alert_type, brand: a.brand_name, domain: a.domain, source: a.source, description: a.description, assignee: a.assignee || "", risk_score: a.risk_score }));
    downloadCSV(rows, "brandsentra_alerts.csv");
  }
  async function exportAlertsSTIX() {
    const alerts = (await dbAll("alerts")).filter((a) => a.status !== "false_positive");
    const bundle = await buildStixBundle(alerts.map((a) => ({ domain: a.domain, risk_score: a.risk_score || 50, risk_level: a.severity, categories: [a.alert_type], first_seen: a.detected_at, last_seen: a.updated_at || a.detected_at, source: a.source || "browser", brand: a.brand_name, alert_type: a.alert_type, description: a.description })));
    downloadJSON(bundle, "brandsentra_stix.json");
  }
  Object.assign(window, { renderAlerts, alertAction, exportAlertsCSV, exportAlertsSTIX });

  // STIX 2.1 (mirrors src/core/stix_export.py; ids are uuid5 over the same namespace)
  const STIX_NS = "6f1c9a4e-2b7d-5e83-9c05-4d8a1f3b7e62";
  const TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";
  async function uuid5(name) {
    const nsBytes = Uint8Array.from(STIX_NS.replace(/-/g, "").match(/.{2}/g).map((h) => parseInt(h, 16)));
    const data = new Uint8Array(nsBytes.length + new TextEncoder().encode(name).length);
    data.set(nsBytes); data.set(new TextEncoder().encode(name), nsBytes.length);
    let hash;
    if (typeof crypto !== "undefined" && crypto.subtle) hash = new Uint8Array(await crypto.subtle.digest("SHA-1", data));
    else { const r = crypto.getRandomValues(new Uint8Array(16)); hash = r; }
    hash[6] = (hash[6] & 0x0f) | 0x50; hash[8] = (hash[8] & 0x3f) | 0x80;
    const hex = Array.from(hash.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
  const stixTs = (d) => new Date(d || Date.now()).toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
  async function buildStixBundle(records) {
    const now = stixTs();
    const identityId = "identity--" + (await uuid5("identity:BrandSentra"));
    const objects = [
      { type: "identity", spec_version: "2.1", id: identityId, created: now, modified: now, name: "BrandSentra", identity_class: "organization", sectors: ["technology"], description: `BrandSentra v${KCW.version} browser export` },
      { type: "marking-definition", spec_version: "2.1", id: TLP_AMBER, created: "2017-01-20T00:00:00.000Z", definition_type: "tlp", name: "TLP:AMBER", definition: { tlp: "amber" } },
    ];
    const seen = new Map();
    for (const r of records) { const d = (r.domain || "").trim().toLowerCase(); if (!d) continue; if (!seen.has(d) || (r.risk_score || 0) > (seen.get(d).risk_score || 0)) seen.set(d, r); }
    for (const r of seen.values()) {
      const created = stixTs(r.first_seen), modified = stixTs(r.last_seen && r.last_seen > r.first_seen ? r.last_seen : r.first_seen);
      const score = Math.max(0, Math.min(100, Number(r.risk_score) || 50));
      const labels = Array.from(new Set([...(r.categories || []), r.risk_level, "phishing", "brandsentra", r.brand ? "brand-impersonation" : null].filter(Boolean))).sort();
      const ind = { type: "indicator", spec_version: "2.1", id: "indicator--" + (await uuid5("indicator:" + r.domain)), created, modified, created_by_ref: identityId, name: r.brand ? `Brand impersonation of ${r.brand}: ${r.domain}` : `Suspected phishing domain: ${r.domain}`, description: r.description || "", indicator_types: [score >= 50 ? "malicious-activity" : "anomalous-activity"], pattern: `[domain-name:value = '${r.domain.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}']`, pattern_type: "stix", pattern_version: "2.1", valid_from: created, labels, confidence: Math.round(score), object_marking_refs: [TLP_AMBER], x_brandsentra_risk_score: score, x_brandsentra_risk_level: r.risk_level };
      if (r.brand) ind.x_brandsentra_brand = r.brand;
      if (r.alert_type) ind.x_brandsentra_alert_type = r.alert_type;
      if (r.source) ind.external_references = [{ source_name: r.source, description: `Observed by BrandSentra (${r.source})` }];
      objects.push(ind);
    }
    return { type: "bundle", id: "bundle--" + (await uuid5(objects.filter((o) => o.type === "indicator").map((o) => o.id).sort().join(","))), objects };
  }

  // ------------------------------------------------------------------ //
  // Domain intel
  // ------------------------------------------------------------------ //
  function quickIntel(domain) { $("intelInput").value = domain; showPage("threatintel"); runIntel(); }
  window.quickIntel = quickIntel;
  async function investigate(domain) {
    const [dns, ct, rdap, uh] = await Promise.allSettled([resolveQuick(domain), fetchCrtSh(domain), fetchRDAP(domain), fetchURLhaus(domain)]);
    const rd = rdap.status === "fulfilled" ? parseRDAP(rdap.value) : null;
    const row = {
      domain, ts: new Date().toISOString(),
      resolves: dns.status === "fulfilled" ? dns.value.resolves : null, ips: dns.status === "fulfilled" ? dns.value.ips : [],
      ct_count: ct.status === "fulfilled" ? ct.value.length : null, ct_first: ct.status === "fulfilled" && ct.value.length ? ct.value.map((c) => c.entry_timestamp).sort()[0] : null,
      registered: rdap.status === "fulfilled" ? true : rdap.reason && rdap.reason.status === 404 ? false : null, rdap: rd,
      urlhaus: uh.status === "fulfilled" && uh.value && uh.value.query_status === "ok" ? { listed: true, url_count: Number(uh.value.url_count || 0), blacklists: uh.value.blacklists || {} } : { error: (uh.value && (uh.value.query_status === "auth_required" ? "auth required" : uh.value.error)) || (uh.reason ? uh.reason.message : "unavailable") },
      errors: [dns, ct, rdap, uh].map((r, i) => (r.status === "rejected" ? ["DNS", "crt.sh", "RDAP", "URLhaus"][i] + ": " + r.reason.message : null)).filter(Boolean),
    };
    const local = engine.detector.analyze(domain);
    let score = local.risk_score;
    const notes = [];
    if (row.urlhaus.listed) { score = Math.max(score, 70); notes.push("listed on URLhaus"); }
    if (rd && rd.age_days !== null && rd.age_days < 30) { score = Math.min(100, score + 15); notes.push(`registered ${rd.age_days} days ago`); }
    if (row.resolves === false) notes.push("does not resolve");
    row.verdict = { score, level: levelOf(score), notes, local_level: local.risk_level, brands: local.matched_brands };
    await dbPut("intel", row);
    return row;
  }
  async function runIntel() {
    const domain = KCW.normalizeDomain($("intelInput").value);
    if (!domain) { toast("Enter a domain", "crit"); return; }
    const btn = $("intelBtn"), panel = $("intelResult");
    btn.disabled = true; btn.textContent = "Working…";
    panel.innerHTML = `<div class="card"><div class="scan-progress"><div class="scan-step running"><span class="step-ico">⏳</span><span>DoH · crt.sh · RDAP · URLhaus for ${esc(domain)}</span></div></div></div>`; panel.classList.add("show");
    try {
      const r = await investigate(domain);
      const v = r.verdict, rd = r.rdap;
      panel.innerHTML = `<div class="card" style="border-left:4px solid ${scoreColor(v.score)}">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px"><div><div style="font-family:var(--font-mono);font-size:1.1rem;font-weight:700">${esc(domain)}</div><div style="font-size:.75rem;color:var(--text-dim)">engine ${esc(v.local_level)}${v.brands.length ? " · targets " + esc(v.brands.join(", ")) : ""}${v.notes.length ? " · " + esc(v.notes.join(" · ")) : ""}</div></div><div style="text-align:right"><div style="font-family:var(--font-mono);font-size:2.2rem;font-weight:800;color:${scoreColor(v.score)}">${Math.round(v.score)}</div><span class="badge ${esc(v.level)}">${esc(v.level)}</span></div></div>
        <dl class="kv-grid" style="margin-top:14px">
          <dt>Resolves</dt><dd>${r.resolves === true ? "yes — " + esc(r.ips.join(", ")) : r.resolves === false ? "no (NXDOMAIN)" : "unknown"}</dd>
          <dt>CT certificates</dt><dd>${r.ct_count === null ? "lookup failed" : r.ct_count + (r.ct_first ? " · first logged " + esc(String(r.ct_first).slice(0, 10)) : "")}</dd>
          <dt>Registered</dt><dd>${r.registered === true ? "yes" : r.registered === false ? "no RDAP record" : "unknown"}${rd && rd.created ? " · " + esc(rd.created.slice(0, 10)) + (rd.age_days !== null ? ` (${rd.age_days} days)` : "") : ""}</dd>
          <dt>Registrar</dt><dd class="wrap">${esc((rd && rd.registrar) || "—")}${rd && rd.abuse ? " · abuse: " + esc(rd.abuse) : ""}</dd>
          <dt>Nameservers</dt><dd class="wrap">${rd && rd.nameservers.length ? rd.nameservers.map(esc).join(", ") : "—"}</dd>
          <dt>URLhaus</dt><dd>${r.urlhaus.error ? "unavailable (" + esc(r.urlhaus.error) + ")" : r.urlhaus.listed ? `<span style="color:var(--red)">listed — ${r.urlhaus.url_count} URL(s)</span>` : "not listed"}</dd>
        </dl>
        ${r.errors.length ? `<div style="margin-top:10px;font-size:.7rem;color:var(--orange)">⚠ ${esc(r.errors.join(" · "))}</div>` : ""}
        <div style="display:flex;gap:8px;margin-top:12px"><button class="btn-sm" onclick="quickScan('${esc(domain)}')">🔍 Full scan</button><button class="btn-sm" onclick="$('ctInput').value='${esc(domain)}';showPage('ctlog');runCTLookup()">📜 CT history</button></div></div>`;
      renderIntelTable();
    } catch (e) { panel.innerHTML = `<div class="card" style="color:var(--red)">Investigation failed: ${esc(e.message)}</div>`; }
    finally { btn.disabled = false; btn.textContent = "🧠 Investigate"; }
  }
  async function renderIntelTable() {
    const rows = (await dbAll("intel")).sort((a, b) => (b.ts > a.ts ? 1 : -1)).slice(0, 50);
    const tb = $("tiTable");
    if (!rows.length) return;
    tb.innerHTML = rows.map((r) => `<tr><td style="font-family:var(--font-mono);font-size:.75rem;cursor:pointer" onclick="quickIntel('${esc(r.domain)}')">${esc(r.domain)}</td><td>${r.resolves === true ? '<span class="sev-crit">● yes</span>' : r.resolves === false ? "no" : "?"}</td><td>${r.ct_count === null ? "?" : r.ct_count}</td><td>${r.registered === true ? "yes" : r.registered === false ? "no" : "?"}</td><td>${r.rdap && r.rdap.age_days !== null ? r.rdap.age_days + "d" : "—"}</td><td>${r.urlhaus.error ? "n/a" : r.urlhaus.listed ? '<span style="color:var(--red)">listed</span>' : "clean"}</td><td><span class="badge ${esc(r.verdict.level)}">${Math.round(r.verdict.score)}</span></td><td style="color:var(--text-dim);font-size:.72rem">${ago(r.ts)}</td></tr>`).join("");
  }
  async function intelOpenAlerts() {
    const open = (await dbAll("alerts")).filter((a) => a.status === "open").map((a) => a.domain);
    const uniq = Array.from(new Set(open)).slice(0, 15);
    if (!uniq.length) { toast("No open alerts", "crit"); return; }
    toast(`Investigating ${uniq.length} domain(s)…`, "ok");
    for (const d of uniq) { try { await investigate(d); } catch (e) { /* continue */ } renderIntelTable(); }
    toast("Done", "ok");
  }
  Object.assign(window, { runIntel, intelOpenAlerts });

  // ------------------------------------------------------------------ //
  // CT / DNS / RDAP explorers
  // ------------------------------------------------------------------ //
  async function runCTLookup() {
    const q = $("ctInput").value.trim();
    if (!q) return;
    const panel = $("ctResult"), btn = $("ctBtn");
    btn.disabled = true; panel.classList.add("show");
    panel.innerHTML = `<div class="card"><div class="scan-step running"><span class="step-ico">⏳</span><span>Querying crt.sh for ${esc(q)}</span></div></div>`;
    try {
      const certs = await fetchCrtSh(q);
      const issuers = {};
      certs.forEach((c) => { issuers[c.issuer_name] = (issuers[c.issuer_name] || 0) + 1; });
      const names = new Set(); certs.forEach((c) => String(c.name_value || "").split("\n").forEach((n) => names.add(n.trim())));
      panel.innerHTML = `<div class="card"><div class="card-header"><span class="card-title">${certs.length} certificates · ${names.size} distinct names</span><button class="btn-sm" onclick="downloadCSV(window.__ct||[],'crtsh_${esc(q.replace(/[^a-z0-9.]/gi, "_"))}.csv')">↧ CSV</button></div>
        <div style="font-size:.72rem;color:var(--text-dim);margin-bottom:10px">Issuers: ${Object.entries(issuers).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => esc(k) + " (" + v + ")").join(" · ") || "—"}</div>
        ${certs.slice(0, 60).sort((a, b) => (b.entry_timestamp > a.entry_timestamp ? 1 : -1)).map((c) => `<div class="cert-card"><div class="cert-cn">${esc(c.common_name || "(no CN)")}</div><div class="cert-meta">${esc(String(c.name_value || "").split("\n").slice(0, 4).join(", "))}</div><div class="cert-meta">Logged ${esc((c.entry_timestamp || "").slice(0, 16))} · valid ${esc((c.not_before || "").slice(0, 10))} → ${esc((c.not_after || "").slice(0, 10))}</div><div class="cert-issuer">${esc(c.issuer_name || "")}</div></div>`).join("") || '<div class="empty-state"><div class="title">No certificates logged</div></div>'}
        ${certs.length > 60 ? `<div style="font-size:.7rem;color:var(--text-muted)">Showing 60 of ${certs.length}</div>` : ""}</div>`;
      window.__ct = certs.map((c) => ({ id: c.id, common_name: c.common_name, names: String(c.name_value || "").replace(/\n/g, "|"), issuer: c.issuer_name, logged: c.entry_timestamp, not_before: c.not_before, not_after: c.not_after }));
    } catch (e) { panel.innerHTML = `<div class="card" style="color:var(--red)">crt.sh lookup failed: ${esc(e.message)} (crt.sh rate-limits heavily; try again in a minute)</div>`; }
    finally { btn.disabled = false; }
  }
  async function runDnsLookup() {
    const d = KCW.normalizeDomain($("dnsInput").value);
    if (!d) return;
    const panel = $("dnsResult"); panel.classList.add("show");
    panel.innerHTML = `<div class="card"><div class="scan-step running"><span class="step-ico">⏳</span><span>Resolving ${esc(d)} via dns.google</span></div></div>`;
    try {
      const recs = await dohAll(d);
      const lines = Object.entries(recs).flatMap(([t, rs]) => rs.map((r) => `<div class="record-line"><span class="record-type">${t}</span><span class="record-val">${esc(r.data)}</span><span class="record-ttl">TTL ${r.ttl}</span></div>`));
      panel.innerHTML = `<div class="card"><div class="card-header"><span class="card-title">${esc(d)}</span><span class="card-sub">${lines.length} record(s)</span></div><div class="record-list">${lines.join("") || '<div style="color:var(--text-muted)">No records — NXDOMAIN or unresolvable</div>'}</div></div>`;
    } catch (e) { panel.innerHTML = `<div class="card" style="color:var(--red)">DNS lookup failed: ${esc(e.message)}</div>`; }
  }
  async function runRdap() {
    const d = KCW.normalizeDomain($("rdapInput").value);
    if (!d) return;
    const panel = $("rdapResult"); panel.classList.add("show");
    panel.innerHTML = `<div class="card"><div class="scan-step running"><span class="step-ico">⏳</span><span>RDAP lookup for ${esc(d)}</span></div></div>`;
    try {
      const raw = await fetchRDAP(d), rd = parseRDAP(raw);
      panel.innerHTML = `<div class="card"><div class="card-header"><span class="card-title">${esc(raw.ldhName || d)}</span><span class="card-sub">${rd.dnssec ? "DNSSEC signed" : "no DNSSEC"}</span></div>
        <dl class="kv-grid"><dt>Registrar</dt><dd class="wrap">${esc(rd.registrar || "—")}</dd><dt>Created</dt><dd>${esc((rd.created || "").slice(0, 10) || "—")}${rd.age_days !== null ? ` (${rd.age_days} days ago)` : ""}</dd><dt>Expires</dt><dd>${esc((rd.expires || "").slice(0, 10) || "—")}</dd><dt>Last changed</dt><dd>${esc((rd.changed || "").slice(0, 10) || "—")}</dd><dt>Nameservers</dt><dd>${rd.nameservers.map(esc).join("<br>") || "—"}</dd><dt>Abuse contact</dt><dd class="wrap">${esc(rd.abuse || "—")}</dd><dt>Status</dt><dd class="wrap">${rd.status.map((s) => `<span class="badge info" style="margin:2px">${esc(s)}</span>`).join("") || "—"}</dd></dl>
        <details style="margin-top:12px;font-size:.7rem;color:var(--text-dim)"><summary>Raw RDAP JSON</summary><pre style="white-space:pre-wrap;max-height:300px;overflow:auto">${esc(JSON.stringify(raw, null, 1))}</pre></details></div>`;
    } catch (e) { panel.innerHTML = `<div class="card" style="color:var(--red)">${e.status === 404 ? esc(d) + " has no RDAP record (not registered, or the registry has no RDAP service)" : "RDAP lookup failed: " + esc(e.message)}</div>`; }
  }
  Object.assign(window, { runCTLookup, runDnsLookup, runRdap });

  // ------------------------------------------------------------------ //
  // History, brands, analytics, notifications, settings
  // ------------------------------------------------------------------ //
  async function renderHistory() {
    const scans = (await dbAll("scans")).sort((a, b) => (b.ts > a.ts ? 1 : -1));
    const tb = $("historyTable");
    tb.innerHTML = scans.length ? scans.slice(0, 500).map((s) => `<tr class="history-row" onclick="quickScan('${esc(s.domain)}')"><td style="font-family:var(--font-mono);font-size:.75rem">${esc(s.domain)}</td><td><span style="font-family:var(--font-mono);font-weight:700;color:${scoreColor(s.score)}">${Math.round(s.score)}</span></td><td><span class="badge ${esc(s.level)}">${esc(s.level)}</span></td><td style="font-size:.72rem">${esc((s.brands || []).join(", "))}</td><td>${(s.categories || []).slice(0, 3).map((c) => `<span class="badge info" style="margin:1px;font-size:.6rem">${esc(c)}</span>`).join("")}</td><td style="color:var(--text-dim);font-size:.7rem;font-family:var(--font-mono)">${fmtTime(s.ts)}</td></tr>`).join("")
      : `<tr><td colspan="6"><div class="empty-state"><div class="ico">📚</div><div class="title">No scans yet</div></div></td></tr>`;
  }
  async function clearHistory() { if (!confirm("Delete all scan history?")) return; await dbClear("scans"); renderHistory(); refreshCounts(); }
  async function exportHistoryJSON() { downloadJSON(await dbAll("scans"), "brandsentra_history.json"); }
  async function exportHistoryCSV() { downloadCSV((await dbAll("scans")).map((s) => ({ domain: s.domain, score: s.score, level: s.level, brands: (s.brands || []).join("|"), categories: (s.categories || []).join("|"), indicators: s.indicators, timestamp: s.ts })), "brandsentra_history.csv"); }
  Object.assign(window, { renderHistory, clearHistory, exportHistoryJSON, exportHistoryCSV });

  async function renderBrandTable() {
    const alerts = await dbAll("alerts");
    const counts = {};
    alerts.forEach((a) => { counts[a.brand_name] = (counts[a.brand_name] || 0) + 1; });
    $("brandTable").innerHTML = engine.brands.map((b) => `<tr><td><strong>${esc(b.name)}</strong></td><td style="font-family:var(--font-mono);font-size:.72rem">${esc(b.domains.join(", "))}</td><td style="font-size:.7rem;color:var(--text-dim)">${esc(b.alias_labels.slice(0, 4).join(", "))}${b.arabic_keywords.length ? ' <span style="color:var(--purple)">' + esc(b.arabic_keywords.slice(0, 2).join(" · ")) + "</span>" : ""}</td><td>${esc(b.industry)}</td><td><span class="badge ${esc(b.priority)}">${esc(b.priority)}</span></td><td style="font-family:var(--font-mono);font-weight:700;color:${counts[b.name] ? "var(--red)" : "var(--green)"}">${counts[b.name] || 0}</td><td><button class="act-btn" onclick="quickSquat('${esc(b.domains[0])}')">🧬 hunt</button></td></tr>`).join("");
  }
  window.renderBrandTable = renderBrandTable;

  async function renderAnalytics() {
    const [scans, alerts, certs] = await Promise.all([dbAll("scans"), dbAll("alerts"), dbAll("certs")]);
    const since = Date.now() - 7 * 86400000;
    const recent = (rows, key) => rows.filter((r) => new Date(r[key]).getTime() >= since);
    setText("anScans", recent(scans, "ts").length); setText("anAlerts", recent(alerts, "detected_at").length); setText("anCerts", recent(certs, "ts").length);
    const triaged = alerts.filter((a) => a.status === "resolved" || a.status === "false_positive").length;
    setText("anFpRate", triaged ? Math.round((100 * alerts.filter((a) => a.status === "false_positive").length) / triaged) + "%" : "—");
    const days = [];
    for (let i = 6; i >= 0; i--) { const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10); days.push(d); }
    const per = (rows, key) => days.map((d) => rows.filter((r) => String(r[key]).slice(0, 10) === d).length);
    const sc = per(scans, "ts"), al = per(alerts, "detected_at");
    renderBarChart("weeklyChart", days.map((d, i) => ({ label: d.slice(5), val: sc[i] + al[i], color: al[i] ? "var(--red)" : "var(--cyan)" })), 170);
    const byBrand = {};
    alerts.forEach((a) => { const k = a.brand_short || a.brand_name; byBrand[k] = (byBrand[k] || 0) + 1; });
    const palette = ["var(--red)", "var(--orange)", "var(--yellow)", "var(--cyan)", "var(--purple)", "var(--green)"];
    renderBarChart("brandChart", Object.entries(byBrand).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v], i) => ({ label: k, val: v, color: palette[i] })), 170);
    const hours = new Array(24).fill(0);
    certs.forEach((c) => { hours[new Date(c.ts).getUTCHours()]++; });
    const max = Math.max(...hours, 1);
    $("hourlyChart").innerHTML = hours.map((v, i) => `<div class="chart-bar" style="height:${Math.max((v / max) * 100, 4)}%;background:${v > max * 0.66 ? "var(--red)" : v > max * 0.33 ? "var(--orange)" : "var(--cyan)"};width:16px" data-label="${i}h" title="${i}:00 UTC — ${v}"></div>`).join("");
  }
  window.renderAnalytics = renderAnalytics;

  async function renderNotifications() {
    $("notifEnabled").checked = !!S.notifEnabled;
    $("notifMinSeverity").value = S.notifMinSeverity;
    const perm = typeof Notification === "undefined" ? "unsupported" : Notification.permission;
    setText("notifStatus", "Permission: " + perm + (S.notifEnabled ? " · enabled for " + S.notifMinSeverity + "+" : " · disabled"));
    const last = (await dbAll("alerts")).sort((a, b) => (b.detected_at > a.detected_at ? 1 : -1))[0];
    if (last) $("webhookPreview").textContent = JSON.stringify({ title: `Brand Alert: ${last.brand_name}`, message: last.description, severity: last.severity, domain: last.domain, alert_type: last.alert_type, details: last.evidence, timestamp: last.detected_at }, null, 2);
  }
  async function toggleNotifications(on) {
    if (on && typeof Notification !== "undefined" && Notification.permission !== "granted") {
      const p = await Notification.requestPermission();
      if (p !== "granted") { $("notifEnabled").checked = false; toast("Notification permission denied", "crit"); return; }
    }
    await saveSetting("notifEnabled", !!on);
    renderNotifications();
  }
  function testNotification() { if (typeof Notification === "undefined" || Notification.permission !== "granted") { toast("Enable notifications first", "crit"); return; } new Notification("BrandSentra test", { body: "Browser notifications are working." }); }
  Object.assign(window, { renderNotifications, toggleNotifications, testNotification });

  function renderKeywords() {
    $("keywordList").innerHTML = S.keywords.map((k) => `<span style="display:inline-block;padding:3px 10px;margin:3px;background:var(--cyan-glow);border:1px solid var(--cyan-dim);border-radius:99px;color:var(--cyan)">${esc(k)} <a href="#" onclick="removeKeyword('${esc(k)}');return false" style="color:var(--text-muted);margin-left:4px">✕</a></span>`).join("");
  }
  async function addKeyword() { const k = $("newKeyword").value.trim().toLowerCase(); if (!k || S.keywords.includes(k)) return; await saveSetting("keywords", S.keywords.concat([k])); $("newKeyword").value = ""; toast("Keyword added — applies to new certificates", "ok"); }
  async function removeKeyword(k) { await saveSetting("keywords", S.keywords.filter((x) => x !== k)); }
  async function resetKeywords() { await saveSetting("keywords", DEFAULTS.keywords.slice()); }
  function renderAllowlist() { $("allowlistList").innerHTML = S.allowlist.length ? S.allowlist.map((d) => `<span style="display:inline-block;padding:3px 10px;margin:3px;background:rgba(0,230,118,.1);border:1px solid var(--green-dim);border-radius:99px;color:var(--green)">${esc(d)} <a href="#" onclick="removeAllowlistDomain('${esc(d)}');return false" style="color:var(--text-muted);margin-left:4px">✕</a></span>`).join("") : '<span style="color:var(--text-muted)">Empty — false positives you allowlist appear here.</span>'; }
  async function addAllowlist() { const d = KCW.normalizeDomain($("newAllow").value); if (!d) return; await addAllowlistDomain(d); $("newAllow").value = ""; }
  async function addAllowlistDomain(domain, quiet) { const d = KCW.normalizeDomain(domain); if (!d) return; if (!S.allowlist.includes(d)) await saveSetting("allowlist", S.allowlist.concat([d])); renderAllowlist(); if (!quiet) toast(d + " allowlisted", "ok"); refreshCounts(); }
  async function removeAllowlistDomain(d) { await saveSetting("allowlist", S.allowlist.filter((x) => x !== d)); renderAllowlist(); refreshCounts(); }
  function renderCustomBrands() { $("customBrandList").innerHTML = S.customBrands.length ? S.customBrands.map((b, i) => `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)"><span><strong>${esc(b.name)}</strong> <span style="color:var(--text-dim)">${esc(b.domains.join(", "))}</span> <span class="badge ${esc(b.priority)}">${esc(b.priority)}</span></span><button class="act-btn danger" onclick="removeCustomBrand(${i})">✕</button></div>`).join("") : '<span style="color:var(--text-muted)">No custom profiles.</span>'; }
  async function addCustomBrand() {
    const name = $("cbName").value.trim(), domains = $("cbDomains").value.split(",").map((s) => KCW.normalizeDomain(s)).filter(Boolean);
    if (!name || !domains.length) { toast("Name and at least one domain are required", "crit"); return; }
    const b = { name, short: $("cbShort").value.trim(), domains, keywords: $("cbKeywords").value.split(",").map((s) => s.trim()).filter(Boolean), arabic: $("cbArabic").value.split(",").map((s) => s.trim()).filter(Boolean), priority: $("cbPriority").value };
    await saveSetting("customBrands", S.customBrands.filter((x) => x.name !== name).concat([b]));
    ["cbName", "cbShort", "cbDomains", "cbKeywords", "cbArabic"].forEach((id) => ($(id).value = ""));
    renderCustomBrands(); toast(`Profile "${name}" added to the engine`, "ok");
  }
  async function removeCustomBrand(i) { const next = S.customBrands.slice(); next.splice(i, 1); await saveSetting("customBrands", next); renderCustomBrands(); }
  function renderSettings() {
    renderKeywords(); renderAllowlist(); renderCustomBrands(); renderRules();
    const dm = $("setDeepMatch"); if (dm) dm.checked = !!S.feedDeepMatch;
    const ae = $("setAutoEnrich"); if (ae) ae.checked = !!S.autoEnrich;
    const fs = $("setFeedSource"); if (fs) fs.value = S.feedSource || "ctlogs";
    const wt = $("setWatchtower"); if (wt) wt.checked = !!S.watchtowerEnabled;
    const wm = $("setWatchtowerMinutes"); if (wm) wm.value = S.watchtowerMinutes || 20;
    const cl = $("setCtLogs"); if (cl) cl.value = (S.ctLogs || []).join("\n");
    const ru = $("setRelayUrl"); if (ru) ru.value = S.relayUrl || "";
    $("setFeedMinScore").value = S.feedMinScore; $("setFeedAlertSeverity").value = S.feedAlertSeverity; $("setCertstreamUrl").value = S.certstreamUrl; $("setApiUrl").value = S.apiUrl;
    checkApi();
    $("aboutText").innerHTML = `BrandSentra v${esc(KCW.version)} · digital risk protection and brand intelligence suite with ${engine.brands.length} brand profiles, ${KCW.data.phishing_keywords.length} lure keywords, ${Object.keys(KCW.data.confusables).length} confusable characters and ${KCW.data.suffixes.free_hosting.length} free-hosting suffixes.<br>Client-side analyst workspace.`;
  }
  function renderRules() {
    const el = $("ruleList");
    if (!el) return;
    el.innerHTML = (S.rules || []).length ? S.rules.map((r, i) => `<div class="rule-row"><label class="toggle" style="margin:0;transform:scale(.8)"><input type="checkbox" ${r.enabled !== false ? "checked" : ""} onchange="toggleRule(${i},this.checked)"><span class="toggle-slider"></span></label><span class="badge ${esc(r.severity || "medium")}" style="font-size:.55rem">${esc(r.severity || "medium")}</span><strong style="font-size:.78rem">${esc(r.name)}</strong><code style="flex:1;font-size:.7rem;word-break:break-all">/${esc(r.pattern)}/${esc(r.flags || "i")}</code><button class="act-btn danger" onclick="removeRule(${i})">✕</button></div>`).join("")
      : '<div style="font-size:.74rem;color:var(--text-muted)">No custom rules yet. Rules are regular expressions tested against every certificate hostname in the live feed and every scanned domain.</div>';
  }
  async function addRule() {
    const name = $("ruleName").value.trim(), pattern = $("rulePattern").value.trim(), severity = $("ruleSeverity").value;
    if (!name || !pattern) { toast("Rule needs a name and a pattern", "crit"); return; }
    try { new RegExp(pattern, "i"); } catch (e) { toast("Invalid regular expression: " + e.message, "crit"); return; }
    const rules = (S.rules || []).concat([{ id: "r" + Date.now().toString(36), name, pattern, flags: "i", severity, enabled: true, created_at: new Date().toISOString() }]);
    await saveSetting("rules", rules);
    $("ruleName").value = ""; $("rulePattern").value = "";
    renderRules(); feed.rules = compileRules(); toast(`Rule "${name}" added`, "ok");
  }
  async function removeRule(i) { const rules = (S.rules || []).slice(); rules.splice(i, 1); await saveSetting("rules", rules); renderRules(); feed.rules = compileRules(); }
  async function toggleRule(i, on) { const rules = (S.rules || []).slice(); rules[i] = Object.assign({}, rules[i], { enabled: !!on }); await saveSetting("rules", rules); feed.rules = compileRules(); }
  function testRules() {
    const host = KCW.normalizeDomain($("ruleTest").value);
    const out = $("ruleTestResult");
    if (!host) { out.textContent = ""; return; }
    const hits = compileRules().filter((r) => r.re.test(host));
    out.innerHTML = hits.length ? hits.map((r) => `<span class="badge ${esc(r.severity)}" style="margin:2px">${esc(r.name)}</span>`).join("") : '<span style="color:var(--text-muted)">no rule matches</span>';
  }
  Object.assign(window, { renderRules, addRule, removeRule, toggleRule, testRules });
  async function exportAllData() {
    const out = {};
    for (const s of ["scans", "alerts", "certs", "sightings", "intel", "settings"]) out[s] = await dbAll(s);
    downloadJSON(Object.assign({ exported_at: new Date().toISOString(), version: KCW.version }, out), "brandsentra_backup.json");
  }
  async function importAllData(file) {
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      for (const s of ["scans", "alerts", "certs", "sightings", "intel", "settings"]) for (const row of data[s] || []) { if (s === "scans" || s === "certs") delete row.id; await dbPut(s, row); }
      await loadSettings(); buildEngine(); renderSettings(); refreshCounts(); toast("Backup restored", "ok");
    } catch (e) { toast("Restore failed: " + e.message, "crit"); }
  }
  async function clearAllData() {
    if (!confirm("Delete ALL local data (scans, alerts, feed matches, sightings, settings)?")) return;
    for (const s of ["scans", "alerts", "certs", "sightings", "intel", "settings"]) await dbClear(s);
    Object.assign(S, JSON.parse(JSON.stringify(DEFAULTS))); buildEngine(); renderSettings(); refreshCounts(); renderDashboard(); toast("Local data cleared", "ok");
  }
  Object.assign(window, { addKeyword, removeKeyword, resetKeywords, addAllowlist, addAllowlistDomain, removeAllowlistDomain, addCustomBrand, removeCustomBrand, renderSettings, exportAllData, importAllData, clearAllData });

  // ------------------------------------------------------------------ //
  // Export helpers & toast
  // ------------------------------------------------------------------ //
  function downloadBlob(blob, filename) { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); }
  function downloadJSON(data, filename) { downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), filename); }
  function downloadCSV(rows, filename) {
    if (!rows.length) { toast("Nothing to export", "crit"); return; }
    const headers = Object.keys(rows[0]);
    const cell = (v) => { if (v == null) return ""; const s = String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    downloadBlob(new Blob([[headers.join(","), ...rows.map((r) => headers.map((h) => cell(r[h])).join(","))].join("\n")], { type: "text/csv" }), filename);
  }
  function toast(msg, type) { const t = $("toast"); t.textContent = msg; t.className = "toast show " + (type || ""); clearTimeout(t._timer); t._timer = setTimeout(() => t.classList.remove("show"), 3500); }
  Object.assign(window, { downloadJSON, downloadCSV, toast, $ });

  // ------------------------------------------------------------------ //
  // Boot
  // ------------------------------------------------------------------ //
  window.addEventListener("DOMContentLoaded", async () => {
    initTheme();
    paintIcons();
    setText("versionBadge", "v" + KCW.version);
    try { await loadSettings(); } catch (e) { console.warn("IndexedDB unavailable", e); }
    buildEngine();
    fillLandingStats();
    if (S.analyst) $("analystName").value = S.analyst;
    if (location.protocol !== "file:") {
      fetchJSON("/api/v1/health", { timeout: 2500 }).then((info) => { const el = $("apiHint"); el.style.display = "block"; el.innerHTML = `This page is served by the BrandSentra API v${esc(info.version)} — configure it under Settings → Backend API to send scans server-side.`; if (!S.apiUrl) S.apiUrl = ""; }).catch(() => { /* static hosting */ });
    }
    let reopen = false;
    try { reopen = sessionStorage.getItem("kcw_open") === "1"; } catch (e) { /* ignore */ }
    if (reopen) enterDashboard();
  });
  window.KCW_APP = {
    feed, engine: () => engine, settings: S, DEFAULTS, PAGE_HOOKS, SEV_RANK,
    db: { all: dbAll, put: dbPut, add: dbAdd, get: dbGet, del: dbDel, clear: dbClear, count: dbCount },
    investigate, buildStixBundle, saveSetting, refreshCounts, renderAlerts, renderDashboard, renderSightings, renderHistory, renderAnalytics,
    persistBrandAlerts, addAllowlistDomain, upsertSighting, resolveQuick, fetchCrtSh, fetchRDAP, parseRDAP, fetchURLhaus, dohAll,
    esc, ago, fmtTime, scoreColor, levelOf, setText, downloadBlob, emit, compileRules,
  };
})();
