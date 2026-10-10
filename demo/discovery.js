/*
 * BrandSentra discovery — no third-party feed required.
 *
 *  1. Direct Certificate Transparency tailing: the browser polls public CT logs
 *     itself (RFC 6962 get-sth / get-entries), parses every DER certificate with
 *     the built-in ASN.1 reader below and hands the hostnames to the feed
 *     pipeline (keyword match → engine score → alerts). Logs are discovered from
 *     Google's public log list when reachable and fall back to known shards.
 *
 *  2. Watchtower: a scheduled brand sweep that generates look-alike domains for
 *     the protected brands and resolves them over DNS-over-HTTPS, recording live
 *     ones as sightings and raising alerts — proactive discovery without waiting
 *     for a certificate to appear.
 */
(function () {
  "use strict";
  const A = window.KCW_APP;
  if (!A) return;
  const { esc, setText, db } = A;
  const S = A.settings;
  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ------------------------------------------------------------------ //
  // Minimal DER / X.509 reader (mirrors src/utils/x509.py)
  // ------------------------------------------------------------------ //
  const OID_CN = [0x55, 0x04, 0x03], OID_O = [0x55, 0x04, 0x0a], OID_SAN = [0x55, 0x1d, 0x11];
  const OID_POISON = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x03];
  const eq = (u8, off, len, oid) => len === oid.length && oid.every((b, i) => u8[off + i] === b);
  const utf8 = new TextDecoder("utf-8");
  function readTLV(u8, off) {
    if (off >= u8.length) throw new Error("eod");
    const tag = u8[off];
    if ((tag & 0x1f) === 0x1f) throw new Error("high tag");
    let pos = off + 1, len = u8[pos++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error("bad length");
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | u8[pos++];
    }
    if (pos + len > u8.length) throw new Error("overflow");
    return { tag, voff: pos, vlen: len };
  }
  function children(u8, off, len) {
    const out = [];
    let pos = off;
    while (pos < off + len) { const t = readTLV(u8, pos); out.push(t); pos = t.voff + t.vlen; }
    return out;
  }
  function parseName(u8, off, len) {
    const out = {};
    for (const set of children(u8, off, len)) {
      if (set.tag !== 0x31) continue;
      for (const s of children(u8, set.voff, set.vlen)) {
        if (s.tag !== 0x30) continue;
        const p = children(u8, s.voff, s.vlen);
        if (p.length < 2 || p[0].tag !== 0x06) continue;
        const key = eq(u8, p[0].voff, p[0].vlen, OID_CN) ? "CN" : eq(u8, p[0].voff, p[0].vlen, OID_O) ? "O" : null;
        if (key && !(key in out)) out[key] = utf8.decode(u8.subarray(p[1].voff, p[1].voff + p[1].vlen));
      }
    }
    return out;
  }
  function decodeTime(t, u8) {
    const s = String.fromCharCode.apply(null, u8.subarray(t.voff, t.voff + t.vlen));
    try {
      if (t.tag === 0x17) { let y = parseInt(s.slice(0, 2), 10); y += y >= 50 ? 1900 : 2000; return new Date(Date.UTC(y, +s.slice(2, 4) - 1, +s.slice(4, 6), +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12))).toISOString(); }
      if (t.tag === 0x18) return new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14) || 0)).toISOString();
    } catch (e) { /* fallthrough */ }
    return null;
  }
  function parseTBS(u8, off, len) {
    const parts = children(u8, off, len);
    let i = 0;
    if (parts[i] && parts[i].tag === 0xa0) i++;
    if (!parts[i] || parts[i].tag !== 0x02) throw new Error("no serial");
    const serial = Array.from(u8.subarray(parts[i].voff, parts[i].voff + parts[i].vlen)).map((b) => b.toString(16).padStart(2, "0")).join("");
    i += 2;
    if (i + 3 >= parts.length) throw new Error("short");
    const issuer = parseName(u8, parts[i].voff, parts[i].vlen); i++;
    const v = children(u8, parts[i].voff, parts[i].vlen); i++;
    const subject = parseName(u8, parts[i].voff, parts[i].vlen); i++;
    let dns = [], poison = false;
    for (const ext of parts.slice(i)) {
      if (ext.tag !== 0xa3) continue;
      const seqs = children(u8, ext.voff, ext.vlen);
      if (!seqs.length) continue;
      for (const e of children(u8, seqs[0].voff, seqs[0].vlen)) {
        if (e.tag !== 0x30) continue;
        const f = children(u8, e.voff, e.vlen);
        if (!f.length || f[0].tag !== 0x06) continue;
        if (eq(u8, f[0].voff, f[0].vlen, OID_POISON)) poison = true;
        if (!eq(u8, f[0].voff, f[0].vlen, OID_SAN)) continue;
        const val = f[f.length - 1];
        if (val.tag !== 0x04) continue;
        const gn = readTLV(u8, val.voff);
        if (gn.tag !== 0x30) continue;
        for (const g of children(u8, gn.voff, gn.vlen)) if (g.tag === 0x82) dns.push(String.fromCharCode.apply(null, u8.subarray(g.voff, g.voff + g.vlen)).trim().toLowerCase());
      }
    }
    const cn = (subject.CN || "").trim().toLowerCase();
    const all = [];
    for (const n of (cn ? [cn] : []).concat(dns)) if (n && !all.includes(n)) all.push(n);
    return { serial_number: serial, issuer, subject, not_before: v[0] ? decodeTime(v[0], u8) : null, not_after: v[1] ? decodeTime(v[1], u8) : null, all_domains: all, is_precert: poison };
  }
  function parseCertificate(u8) {
    const outer = readTLV(u8, 0);
    if (outer.tag !== 0x30) throw new Error("not a certificate");
    const inner = children(u8, outer.voff, outer.vlen);
    if (inner.length && inner[0].tag === 0x30) return parseTBS(u8, inner[0].voff, inner[0].vlen);
    return parseTBS(u8, outer.voff, outer.vlen);
  }
  function b64ToBytes(b64) { const bin = atob(b64); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return u8; }
  function parseLeafInput(b64) {
    const raw = b64ToBytes(b64);
    if (raw.length < 12 || raw[0] !== 0 || raw[1] !== 0) throw new Error("bad leaf");
    let ts = 0;
    for (let i = 2; i < 10; i++) ts = ts * 256 + raw[i];
    const entryType = (raw[10] << 8) | raw[11];
    let pos = 12, kind;
    if (entryType === 1) { pos += 32; kind = "precert"; } else if (entryType === 0) kind = "x509"; else throw new Error("entry type");
    const len = (raw[pos] << 16) | (raw[pos + 1] << 8) | raw[pos + 2];
    pos += 3;
    const parsed = parseCertificate(raw.subarray(pos, pos + len));
    parsed.entry_type = kind; parsed.timestamp = ts;
    return parsed;
  }
  function parseTileLeaf(u8, offset) {
    if (offset + 10 > u8.length) throw new Error("tile leaf too short");
    let ts = 0;
    for (let i = 0; i < 8; i++) ts = ts * 256 + u8[offset + i];
    const entryType = (u8[offset + 8] << 8) | u8[offset + 9];
    let pos = offset + 10;
    const take = (n) => { if (pos + n > u8.length) throw new Error("tile leaf truncated"); let len = 0; for (let i = 0; i < n; i++) len = (len << 8) | u8[pos + i]; pos += n; if (pos + len > u8.length) throw new Error("tile leaf truncated"); const chunk = u8.subarray(pos, pos + len); pos += len; return chunk; };
    let der, kind;
    if (entryType === 0) { der = take(3); kind = "x509"; } else if (entryType === 1) { pos += 32; der = take(3); kind = "precert"; } else throw new Error("entry type");
    take(2);
    if (entryType === 1) take(3);
    take(2);
    const parsed = parseCertificate(der);
    parsed.entry_type = kind; parsed.timestamp = ts;
    return { parsed, next: pos };
  }
  function parseDataTile(u8) {
    const out = [];
    let pos = 0;
    while (pos < u8.length) { const r = parseTileLeaf(u8, pos); out.push(r.parsed); pos = r.next; }
    return out;
  }
  function tilePath(index) {
    let d = String(index);
    d = d.padStart(Math.ceil(d.length / 3) * 3, "0");
    const groups = d.match(/.{3}/g);
    return groups.slice(0, -1).map((g) => "x" + g).concat([groups[groups.length - 1]]).join("/");
  }
  function parseCheckpoint(text) { const lines = text.trim().split("\n"); if (lines.length < 3) throw new Error("malformed checkpoint"); const n = parseInt(lines[1].trim(), 10); if (!Number.isFinite(n)) throw new Error("bad checkpoint size"); return n; }
  const TILE_WIDTH = 256;
  const toMessage = (p, logName, index) => ({
    message_type: "certificate_update",
    data: { update_type: p.entry_type === "precert" ? "PrecertLogEntry" : "X509LogEntry", leaf_cert: { subject: { CN: p.subject.CN || "" }, issuer: p.issuer, all_domains: p.all_domains, not_before: p.not_before, not_after: p.not_after, serial_number: p.serial_number, fingerprint: "" }, cert_index: index, seen: p.timestamp / 1000, source: { name: logName, url: "" } },
  });

  // ------------------------------------------------------------------ //
  // Direct CT log tailer
  // ------------------------------------------------------------------ //
  const LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
  const FALLBACK_LOGS = [
    ["Google Argon 2026h2", "https://ct.googleapis.com/logs/us1/argon2026h2/"], ["Google Argon 2027h1", "https://ct.googleapis.com/logs/us1/argon2027h1/"],
    ["Google Xenon 2026h2", "https://ct.googleapis.com/logs/eu1/xenon2026h2/"], ["Google Xenon 2027h1", "https://ct.googleapis.com/logs/eu1/xenon2027h1/"],
    ["Cloudflare Nimbus 2026", "https://ct.cloudflare.com/logs/nimbus2026/"], ["Cloudflare Nimbus 2027", "https://ct.cloudflare.com/logs/nimbus2027/"],
    ["Let's Encrypt Oak 2026h2", "https://oak.ct.letsencrypt.org/2026h2/"], ["Let's Encrypt Oak 2027h1", "https://oak.ct.letsencrypt.org/2027h1/"],
    ["DigiCert Wyvern 2026h2", "https://wyvern.ct.digicert.com/2026h2/"], ["DigiCert Sphinx 2026h2", "https://sphinx.ct.digicert.com/2026h2/"],
    ["Sectigo Sabre 2026h2", "https://sabre2026h2.ct.sectigo.com/"], ["Sectigo Mammoth 2026h2", "https://mammoth2026h2.ct.sectigo.com/"],
  ].map(([name, url]) => ({ name, url, kind: "rfc6962" }));
  const FALLBACK_STATIC_LOGS = [
    ["Geomys Tuscolo 2026h2", "https://tuscolo2026h2.sunlight.geomys.org/"], ["Geomys Tuscolo 2027h1", "https://tuscolo2027h1.sunlight.geomys.org/"],
    ["Let's Encrypt Sycamore 2026h2", "https://sycamore.ct.letsencrypt.org/2026h2/"], ["Let's Encrypt Willow 2026h2", "https://willow.ct.letsencrypt.org/2026h2/"],
  ].map(([name, url]) => ({ name, url, kind: "static" }));

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

  async function getRaw(url, timeout, asText) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout || 10000);
    try {
      const target = proxyUrl(url);
      const r = await fetch(target, { mode: "cors", cache: "no-store", signal: ctrl.signal });
      if (!r.ok) { const e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
      return asText ? await r.text() : new Uint8Array(await r.arrayBuffer());
    } finally { clearTimeout(t); }
  }
  async function getJSON(url, timeout) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout || 10000);
    try {
      const target = proxyUrl(url);
      const r = await fetch(target, { mode: "cors", cache: "no-store", signal: ctrl.signal });
      if (!r.ok) { const e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
      return await r.json();
    } finally { clearTimeout(t); }
  }
  // A shard's temporal interval is the range of certificate expiry dates it accepts, so a certificate
  // issued today lands in a shard up to one lifetime ahead. Keep every shard that has not ended and
  // starts within that lifetime (200 days, the CA/Browser Forum cap during 2026).
  const MAX_CERT_LIFETIME_MS = 200 * 864e5;
  function selectLogs(list, now) {
    const out = [];
    for (const op of list.operators || []) {
      for (const [kind, key, urlKey] of [["rfc6962", "logs", "url"], ["static", "tiled_logs", "monitoring_url"]]) {
        for (const log of op[key] || []) {
          const state = log.state || {};
          if (!("usable" in state || "qualified" in state)) continue;
          const iv = log.temporal_interval;
          if (iv) { const s = Date.parse(iv.start_inclusive), e = Date.parse(iv.end_exclusive); if (!(e > now && s < now + MAX_CERT_LIFETIME_MS)) continue; }
          if (!String(log[urlKey] || "").startsWith("https://")) continue;
          const opName = String(op.name || "log").trim();
          let desc = String(log.description || "").trim().replace(/^['"]|['"]$/g, "");
          if (desc.toLowerCase().startsWith(opName.toLowerCase())) desc = desc.slice(opName.length).replace(/^[\s\-'"]+/, "");
          out.push({ name: `${opName} ${desc}`.trim(), url: String(log[urlKey]).replace(/\/+$/, "") + "/", kind });
        }
      }
    }
    return out.slice(0, 8);
  }

  const CT = {
    running: false, feed: null, logs: [], candidates: [], renderTimer: null, generation: 0,
    stats: { entries: 0, skipped: 0, parseErrors: 0, requests: 0, errors: 0, startedAt: null },
    batch: 256, pollMs: 2000, maxLag: 4000,
    async start(feed) {
      this.stop();
      const gen = ++this.generation;
      this.feed = feed; this.running = true; this.stats = { entries: 0, skipped: 0, parseErrors: 0, requests: 0, errors: 0, startedAt: Date.now() };
      feed.setState("connecting", "probing CT logs");
      await this.discover();
      if (gen !== this.generation) return;
      this.render();
      if (!this.logs.length) { feed.setState("offline", "no CT log reachable — check network / try Replay"); return; }
      feed.retry = 0;
      feed.setState("live", `${this.logs.length} CT logs · ${feed.keywords.length} keywords`);
      feed.startRate();
      this.logs.forEach((log) => this.tail(log, gen));
      this.renderTimer = setInterval(() => this.render(), 1000);
    },
    stop() { this.running = false; this.generation++; clearInterval(this.renderTimer); this.logs.forEach((l) => (l.active = false)); },
    async discover() {
      const gen = this.generation;
      let cands = (S.ctLogs || []).map((u) => { const [url, kind] = String(u).split(/\s+/); return { name: url.replace(/^https?:\/\//, "").replace(/\/$/, ""), url: url.replace(/\/+$/, "") + "/", kind: kind === "static" ? "static" : "rfc6962" }; });
      if (!cands.length) {
        try { cands = selectLogs(await getJSON(LOG_LIST_URL, 8000), Date.now()); } catch (e) { cands = []; }
        if (!cands.length) cands = FALLBACK_LOGS.concat(FALLBACK_STATIC_LOGS);
      }
      if (cands.length > 8) cands = cands.slice(0, 8);
      if (gen !== this.generation) return [];
      const candidates = cands.map((c) => Object.assign({ status: "probing", tree_size: 0, cursor: null, entries: 0, skipped: 0, errors: 0, backoff: 0, active: false, rate: 0, lastCount: 0 }, c));
      this.candidates = candidates;
      await Promise.allSettled(candidates.map(async (log) => {
        try {
          log.tree_size = await this.treeSize(log);
          log.cursor = Math.max(0, log.tree_size - this.batch);
          log.status = "live"; log.active = true;
        } catch (e) { log.status = "unreachable"; log.error = e.name === "AbortError" ? "timeout" : e.message; }
      }));
      if (gen !== this.generation) { candidates.forEach((l) => (l.active = false)); return []; }
      this.logs = candidates.filter((l) => l.active);
      return this.logs;
    },
    async treeSize(log) {
      this.stats.requests++;
      if (log.kind === "static") return parseCheckpoint(await getRaw(log.url + "checkpoint", 8000, true));
      const sth = await getJSON(log.url + "ct/v1/get-sth", 8000);
      return Number(sth.tree_size) || 0;
    },
    async fetchEntries(log) {
      // Returns [{index, parsed}] for the next batch; unparsable entries are counted and skipped.
      const out = [];
      this.stats.requests++;
      if (log.kind === "static") {
        const tile = Math.floor(log.cursor / TILE_WIDTH), start = tile * TILE_WIDTH;
        const width = Math.min(TILE_WIDTH, log.tree_size - start);
        const data = await getRaw(`${log.url}tile/data/${tilePath(tile)}${width === TILE_WIDTH ? "" : ".p/" + width}`, 15000, false);
        let leaves = [];
        try { leaves = parseDataTile(data); } catch (e) { this.stats.parseErrors++; }
        leaves.forEach((parsed, i) => { if (start + i >= log.cursor) out.push({ index: start + i, parsed }); });
        if (!leaves.length) out.push({ index: start + width - 1, parsed: null });
        return out;
      }
      const end = Math.min(log.cursor + this.batch, log.tree_size) - 1;
      const payload = await getJSON(`${log.url}ct/v1/get-entries?start=${log.cursor}&end=${end}`, 15000);
      (payload.entries || []).forEach((e, i) => { let parsed = null; try { parsed = parseLeafInput(e.leaf_input); } catch (err) { this.stats.parseErrors++; } out.push({ index: log.cursor + i, parsed }); });
      return out;
    },
    async tail(log, gen) {
      while (this.running && log.active && gen === this.generation) {
        let processed = 0;
        try {
          log.tree_size = await this.treeSize(log);
          if (log.tree_size - log.cursor > this.maxLag) { const skip = log.tree_size - this.batch - log.cursor; log.skipped += skip; this.stats.skipped += skip; log.cursor = log.tree_size - this.batch; }
          if (log.cursor < log.tree_size) {
            const entries = await this.fetchEntries(log);
            for (const e of entries) {
              if (!e.parsed) continue;
              if (!this.running || gen !== this.generation) return;
              try { await this.feed.handle(toMessage(e.parsed, log.name, e.index)); } catch (err) { /* pipeline error */ }
            }
            processed = entries.length;
            if (entries.length) log.cursor = entries[entries.length - 1].index + 1;
            log.entries += processed; this.stats.entries += processed;
          }
          log.backoff = 0; log.status = "live";
        } catch (e) {
          log.errors++; this.stats.errors++;
          const floor = e.status === 429 ? 30000 : 2000;
          log.backoff = Math.min(120000, Math.max(floor, (log.backoff || floor) * 2));
          log.status = e.status === 429 ? "rate-limited" : "error";
          log.error = e.name === "AbortError" ? "timeout" : e.message;
        }
        const wait = log.backoff || (processed >= this.batch ? 1000 : this.pollMs);
        await sleep(wait);
      }
    },
    coverage() { const seen = this.stats.entries + this.stats.skipped; return seen ? Math.round((1000 * this.stats.entries) / seen) / 10 : 100; },
    render() {
      const tb = $("ctLogTable");
      if (tb) {
        const now = Date.now();
        tb.innerHTML = this.candidates.length ? this.candidates.map((l) => {
          const rate = l._t ? Math.round(((l.entries - l.lastCount) * 1000) / Math.max(1, now - l._t)) : 0;
          l.lastCount = l.entries; l._t = now;
          const cls = l.status === "live" ? "low" : l.status === "unreachable" ? "clean" : l.status === "rate-limited" ? "medium" : "high";
          return `<tr><td style="font-size:.75rem"><strong>${esc(l.name)}</strong> <span class="badge ${l.kind === "static" ? "info" : "clean"}" style="font-size:.55rem">${l.kind === "static" ? "static ct" : "rfc 6962"}</span><div style="font-family:var(--font-mono);font-size:.62rem;color:var(--text-muted)">${esc(l.url)}</div></td><td><span class="badge ${cls}">${esc(l.status)}</span>${l.error && l.status !== "live" ? `<div style="font-size:.62rem;color:var(--text-muted)">${esc(l.error)}</div>` : ""}</td><td style="font-family:var(--font-mono);font-size:.72rem">${l.tree_size ? l.tree_size.toLocaleString() : "—"}</td><td style="font-family:var(--font-mono);font-size:.72rem">${l.entries.toLocaleString()}</td><td style="font-family:var(--font-mono);font-size:.72rem">${l.active ? rate + "/s" : "—"}</td><td style="font-family:var(--font-mono);font-size:.72rem;color:var(--text-muted)">${l.skipped ? l.skipped.toLocaleString() : "0"}</td></tr>`;
        }).join("") : '<tr><td colspan="6" style="color:var(--text-muted);font-size:.75rem;padding:14px">Not started</td></tr>';
      }
      setText("ctCoverage", this.logs.length ? this.coverage() + "%" : "—");
      setText("ctLogsLive", `${this.logs.length} / ${this.candidates.length}`);
      setText("ctEntries", this.stats.entries.toLocaleString());
      setText("ctErrors", `${this.stats.errors} errors · ${this.stats.parseErrors} unparsable`);
    },
  };

  // ------------------------------------------------------------------ //
  // Relay feed: matches published by the scheduled backend tailer (same origin)
  // ------------------------------------------------------------------ //
  const RELAY = {
    timer: null, feed: null, last: null, generatedAt: null, rows: 0, seen: new Set(), state: "idle", error: null,
    url() { return (S.relayUrl && S.relayUrl.trim()) || "feed/latest.json"; },
    start(feed) {
      this.stop();
      if (location.protocol === "file:" && !S.relayUrl) { this.state = "unavailable"; return; }
      this.feed = feed;
      this.tick();
      this.timer = setInterval(() => this.tick(), 5 * 60000);
    },
    stop() { clearInterval(this.timer); this.timer = null; },
    async tick() {
      try {
        const data = await getJSON(this.url() + (this.url().includes("?") ? "&" : "?") + "t=" + Date.now(), 10000);
        this.state = "live"; this.error = null; this.last = Date.now(); this.generatedAt = data.generated_at;
        const watermark = S.relayWatermark || "";
        let newest = watermark, added = 0;
        for (const m of data.matches || []) {
          const key = m.domain + "|" + m.ts;
          if (this.seen.has(key) || (m.ts || "") <= watermark) continue;
          this.seen.add(key);
          if (m.ts > newest) newest = m.ts;
          added++;
          await this.feed.handle({ message_type: "certificate_update", data: { source: { name: "relay:" + (m.log || "ct") }, leaf_cert: { all_domains: [m.domain], issuer: { O: m.issuer || "" }, not_before: m.not_before } } }, false);
        }
        this.rows = (data.matches || []).length;
        if (newest !== watermark) A.saveSetting("relayWatermark", newest);
        if (added && this.feed.state !== "live") this.feed.setState("live", `relay feed · ${added} new match(es)`);
      } catch (e) { this.state = e.status === 404 ? "not published yet" : "unreachable"; this.error = e.message; }
      this.render();
    },
    render() {
      const el = $("relayStatus");
      if (!el) return;
      const age = this.generatedAt ? Math.round((Date.now() - Date.parse(this.generatedAt)) / 60000) : null;
      el.textContent = this.state === "live" ? `Relay feed: ${this.rows} matches · snapshot ${age === null ? "" : age + " min old"}` : this.state === "unavailable" ? "Relay feed: available on the hosted site" : `Relay feed: ${this.state}`;
      el.style.color = this.state === "live" ? "var(--green)" : "var(--text-muted)";
    },
  };
  const origStart = CT.start.bind(CT), origStop = CT.stop.bind(CT);
  CT.start = async function (feed) { RELAY.start(feed); return origStart(feed); };
  CT.stop = function () { RELAY.stop(); return origStop(); };
  const origRender = CT.render.bind(CT);
  CT.render = function () { origRender(); RELAY.render(); };
  window.KCW_RELAY = RELAY;

  // ------------------------------------------------------------------ //
  // Watchtower: scheduled proactive brand sweeps
  // ------------------------------------------------------------------ //
  const WT = {
    timer: null, running: false, cursor: 0, last: null, next: null, lastFound: 0, lastChecked: 0, sweeping: false,
    TLDS: ["com", "net", "org", "kw", "com.kw", "xyz", "top", "online", "site", "icu", "club", "info", "app", "shop", "live"],
    start() {
      this.stop();
      if (!S.watchtowerEnabled) { this.render(); return; }
      this.running = true;
      const first = 45000;
      this.next = Date.now() + first;
      this.timer = setTimeout(() => this.cycle(), first);
      this.render();
    },
    stop() { clearTimeout(this.timer); this.running = false; this.next = null; this.render(); },
    async cycle() {
      if (!this.running) return;
      try { await this.sweep(); } catch (e) { console.warn("watchtower", e); }
      if (!this.running) return;
      const period = Math.max(5, Number(S.watchtowerMinutes) || 20) * 60000;
      this.next = Date.now() + period;
      this.timer = setTimeout(() => this.cycle(), period);
      this.render();
    },
    async sweep(brandsPerCycle) {
      if (this.sweeping) return { checked: 0, found: 0 };
      this.sweeping = true;
      const engine = A.engine();
      const rank = { critical: 0, high: 1, medium: 2, low: 3 };
      const brands = engine.brands.slice().sort((a, b) => (rank[a.priority] ?? 9) - (rank[b.priority] ?? 9));
      const per = brandsPerCycle || Math.max(1, Number(S.watchtowerBrands) || 4);
      const picked = [];
      for (let i = 0; i < per && brands.length; i++) picked.push(brands[(this.cursor + i) % brands.length]);
      this.cursor = (this.cursor + per) % Math.max(1, brands.length);
      let checked = 0, found = 0, newAlerts = 0;
      for (const b of picked) {
        const domain = b.domains[0];
        if (!domain) continue;
        const perms = engine.analyzer.generatePermutationsDetailed(domain, { tlds: this.TLDS, includeCombos: true, includeHomoglyphs: true, maxResults: Math.max(10, Number(S.watchtowerPerBrand) || 60) }).filter((p) => !engine.analyzer.isLegitimate(p.domain) && !engine.isAllowlisted(p.domain));
        for (let i = 0; i < perms.length && this.running !== false; i += 8) {
          await Promise.all(perms.slice(i, i + 8).map(async (p) => {
            checked++;
            const r = await A.resolveQuick(p.domain);
            if (r.resolves !== true) return;
            found++;
            const s = await A.upsertSighting(p.domain, domain, p.technique, r.ips);
            if (s.is_new) {
              const alerts = engine.monitor.checkDomain(p.domain, "watchtower", true);
              if (alerts.length) { await A.persistBrandAlerts(alerts, "watchtower", { ips: r.ips, technique: p.technique, protected_domain: domain }); newAlerts += alerts.length; }
            }
          }));
        }
        this.render(`${b.short_name || b.name}: ${checked} checked`);
      }
      this.last = Date.now(); this.lastFound = found; this.lastChecked = checked;
      this.sweeping = false;
      A.saveSetting("lastWatchtower", new Date(this.last).toISOString());
      if (found) toast(`Watchtower: ${found} live look-alike(s) found (${newAlerts} new alerts)`, "crit"); else if (checked) toast(`Watchtower sweep: ${checked} look-alikes checked, none resolving`, "ok");
      A.refreshCounts();
      if ($("page-sightings") && $("page-sightings").classList.contains("active")) A.renderSightings();
      this.render();
      return { checked, found, newAlerts };
    },
    render(progress) {
      const el = $("wtStatus");
      if (!el) return;
      const mins = (ms) => Math.max(0, Math.round(ms / 60000));
      let text;
      if (this.sweeping) text = `Sweeping… ${progress || ""}`;
      else if (!S.watchtowerEnabled) text = "Watchtower is off — enable it to sweep protected brands automatically";
      else if (this.next) { const left = this.next - Date.now(); text = `Next sweep ${left < 60000 ? "in under a minute" : "in " + mins(left) + " min"}` + (this.last ? ` · last: ${this.lastChecked} checked, ${this.lastFound} live` : ""); }
      else text = "Watchtower idle";
      el.textContent = text;
      const t = $("wtToggle"); if (t) t.checked = !!S.watchtowerEnabled;
      const t2 = $("setWatchtower"); if (t2) t2.checked = !!S.watchtowerEnabled;
    },
  };
  async function setWatchtower(onOff) { await A.saveSetting("watchtowerEnabled", !!onOff); if (onOff) WT.start(); else WT.stop(); }
  async function runWatchtowerNow() { if (WT.sweeping) { toast("A sweep is already running"); return; } toast("Watchtower sweep started"); WT.render("starting"); await WT.sweep(); }

  window.addEventListener("kcw:enter", () => { WT.start(); });
  window.addEventListener("kcw:page", (e) => { if (e.detail && e.detail.id === "sightings") WT.render(); if (e.detail && e.detail.id === "certstream") CT.render(); });
  setInterval(() => { if ($("page-sightings") && $("page-sightings").classList.contains("active")) WT.render(); }, 30000);

  window.KCW_CT = CT;
  window.KCW_WT = WT;
  window.KCW_X509 = { parseCertificate, parseLeafInput, parseTBS, parseTileLeaf, parseDataTile, tilePath, parseCheckpoint, readTLV, selectLogs, FALLBACK_LOGS, FALLBACK_STATIC_LOGS };
  Object.assign(window, { setWatchtower, runWatchtowerNow });
})();
