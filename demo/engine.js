/*
 * BrandSentra browser detection engine.
 *
 * A faithful JavaScript port of the Python engine (src/utils/domain.py,
 * src/core/domain_analyzer.py, src/core/brand_monitor.py,
 * src/core/phishing_detector.py). All data tables come from engine-data.js,
 * which is generated from the Python sources; tests/test_js_engine.py checks
 * that both engines agree on a corpus of domains.
 *
 * Works as a classic <script> in browsers and via require() in Node.
 */
(function (global) {
  "use strict";
  const D = global.KCW_DATA;
  if (!D) throw new Error("engine-data.js must be loaded before engine.js");

  // ------------------------------------------------------------------ //
  // Punycode (RFC 3492)
  // ------------------------------------------------------------------ //
  const PC = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, initialBias: 72, initialN: 128 };
  function pcAdapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / PC.damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((PC.base - PC.tMin) * PC.tMax) >> 1) {
      delta = Math.floor(delta / (PC.base - PC.tMin));
      k += PC.base;
    }
    return k + Math.floor(((PC.base - PC.tMin + 1) * delta) / (delta + PC.skew));
  }
  function pcDigit(d) {
    return String.fromCharCode(d + 22 + 75 * (d < 26));
  }
  function punycodeEncode(input) {
    const cps = Array.from(input, (c) => c.codePointAt(0));
    let n = PC.initialN, delta = 0, bias = PC.initialBias;
    let output = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join("");
    const basicLength = output.length;
    let handled = basicLength;
    if (basicLength) output += "-";
    while (handled < cps.length) {
      let m = 0x7fffffff;
      for (const c of cps) if (c >= n && c < m) m = c;
      delta += (m - n) * (handled + 1);
      n = m;
      for (const c of cps) {
        if (c < n) delta++;
        if (c === n) {
          let q = delta;
          for (let k = PC.base; ; k += PC.base) {
            const t = k <= bias ? PC.tMin : k >= bias + PC.tMax ? PC.tMax : k - bias;
            if (q < t) break;
            output += pcDigit(t + ((q - t) % (PC.base - t)));
            q = Math.floor((q - t) / (PC.base - t));
          }
          output += pcDigit(q);
          bias = pcAdapt(delta, handled + 1, handled === basicLength);
          delta = 0;
          handled++;
        }
      }
      delta++;
      n++;
    }
    return output;
  }
  function punycodeDecode(input) {
    const output = [];
    let basic = input.lastIndexOf("-");
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error("not basic");
      output.push(input.charCodeAt(j));
    }
    let n = PC.initialN, bias = PC.initialBias, i = 0;
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
      const oldi = i;
      for (let w = 1, k = PC.base; ; k += PC.base) {
        if (index >= input.length) throw new Error("invalid punycode");
        const cp = input.charCodeAt(index++);
        const digit = cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : PC.base;
        if (digit >= PC.base) throw new Error("invalid digit");
        i += digit * w;
        const t = k <= bias ? PC.tMin : k >= bias + PC.tMax ? PC.tMax : k - bias;
        if (digit < t) break;
        w *= PC.base - t;
      }
      const out = output.length + 1;
      bias = pcAdapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  // ------------------------------------------------------------------ //
  // Suffix knowledge & character tables
  // ------------------------------------------------------------------ //
  const FREE_HOSTING = new Set(D.suffixes.free_hosting);
  const ALL_SUFFIXES = new Set([].concat(D.suffixes.regional || D.suffixes._ || [], D.suffixes.gcc_mena, D.suffixes.global, D.suffixes.free_hosting));
  let MAX_SUFFIX_LABELS = 1;
  for (const s of ALL_SUFFIXES) MAX_SUFFIX_LABELS = Math.max(MAX_SUFFIX_LABELS, s.split(".").length);
  const CONFUSABLES = D.confusables;
  const LEET_MAP = D.leet_map;
  const VISUAL_SEQUENCES = D.visual_sequences;
  const HIGH_TLDS = new Set(D.high_risk_tlds), MEDIUM_TLDS = new Set(D.medium_risk_tlds);
  const PHISHING_KEYWORDS = new Set(D.phishing_keywords);
  const COMBO_KEYWORDS = new Set(D.combo_keywords);
  const CONTEXT_TOKENS = new Set(D.context_tokens);
  const VOCABULARY = new Set([...COMBO_KEYWORDS, ...CONTEXT_TOKENS]);
  const OFFICIAL_SUFFIXES = new Set(D.official_suffixes);
  const OFFICIAL_TOKENS = new Set(D.official_tokens);
  const EMBEDDED_TLD_TOKENS = new Set(D.embedded_tld_tokens);

  const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const SCHEME_RE = /^[a-z][a-z0-9+.\-]*:\/\//i;
  const LABEL_OK_RE = /^[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?$/;
  const ARABIC_DIACRITICS = /[ؐ-ًؚ-ٰٟۖ-ۭـ]/g;
  const ARABIC_RANGE = /[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]/;
  const ARABIC_FOLD = { "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ة": "ه", "ى": "ي", "ئ": "ي", "ؤ": "و", "گ": "ك", "ک": "ك", "ی": "ي", "ے": "ي" };

  // ------------------------------------------------------------------ //
  // Domain utilities
  // ------------------------------------------------------------------ //
  function isAscii(s) {
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false;
    return true;
  }
  function toAsciiLabel(label) {
    if (isAscii(label)) return label;
    try {
      return "xn--" + punycodeEncode(label.normalize("NFC"));
    } catch (e) {
      return label.normalize("NFKC");
    }
  }
  function normalizeDomain(raw) {
    if (raw === null || raw === undefined) return "";
    let v = String(raw).trim();
    if (!v) return "";
    v = v.replace(SCHEME_RE, "");
    for (const sep of ["/", "?", "#", "\\"]) {
      const i = v.indexOf(sep);
      if (i !== -1) v = v.slice(0, i);
    }
    if (v.includes("@")) v = v.slice(v.lastIndexOf("@") + 1);
    if ((v.match(/:/g) || []).length === 1) {
      const [host, port] = v.split(":");
      if (/^\d+$/.test(port)) v = host;
    }
    v = v.trim().replace(/^\.+|\.+$/g, "").toLowerCase();
    if (v.startsWith("*.")) v = v.slice(2);
    v = v.replace(/^\.+/, "");
    return v.split(".").filter(Boolean).map(toAsciiLabel).join(".");
  }
  function toUnicode(hostname) {
    return hostname.split(".").map((l) => {
      if (l.startsWith("xn--")) {
        try { return punycodeDecode(l.slice(4)); } catch (e) { return l; }
      }
      return l;
    }).join(".");
  }
  function splitSuffix(labels) {
    if (!labels.length) return [[], ""];
    for (let n = Math.min(MAX_SUFFIX_LABELS, labels.length - 1); n > 1; n--) {
      const cand = labels.slice(-n).join(".");
      if (ALL_SUFFIXES.has(cand)) return [labels.slice(0, -n), cand];
    }
    if (labels.length === 1) return [[], labels[0]];
    return [labels.slice(0, -1), labels[labels.length - 1]];
  }
  function parseDomain(raw) {
    const original = raw === null || raw === undefined ? "" : String(raw);
    const stripped = original.trim().toLowerCase();
    const isWildcard = stripped.startsWith("*.");
    const hostname = normalizeDomain(original);
    const p = {
      original, hostname, unicode_hostname: hostname, labels: [], subdomain: "", label: "", suffix: "", tld: "",
      registrable: "", is_idn: false, is_wildcard: isWildcard, is_ip: false, hosting_platform: null,
      unicode_labels: [], valid: true,
    };
    if (!hostname) { p.valid = false; return finishParsed(p); }
    if (IPV4_RE.test(hostname)) {
      p.labels = hostname.split("."); p.label = hostname; p.registrable = hostname; p.is_ip = true;
      p.unicode_labels = p.labels.slice();
      return finishParsed(p);
    }
    p.labels = hostname.split(".");
    p.unicode_hostname = toUnicode(hostname);
    p.unicode_labels = p.unicode_hostname.split(".");
    p.is_idn = p.labels.some((l) => l.startsWith("xn--")) || !isAscii(hostname);
    const [rest, suffix] = splitSuffix(p.labels);
    p.suffix = suffix;
    p.hosting_platform = FREE_HOSTING.has(suffix) ? suffix : null;
    if (rest.length) {
      p.label = rest[rest.length - 1];
      p.subdomain = rest.slice(0, -1).join(".");
      p.registrable = suffix ? p.label + "." + suffix : p.label;
    } else {
      p.registrable = suffix;
    }
    p.tld = p.labels[p.labels.length - 1];
    p.valid = p.labels.every((l) => LABEL_OK_RE.test(l)) && hostname.length <= 253;
    return finishParsed(p);
  }
  function finishParsed(p) {
    p.depth = p.labels.length;
    p.subdomain_labels = p.subdomain ? p.subdomain.split(".").filter(Boolean) : [];
    const nSuffix = p.suffix ? p.suffix.split(".").length : 0;
    p.searchable_labels = nSuffix ? p.labels.slice(0, p.labels.length - nSuffix) : p.labels.slice();
    p.searchable_text = p.searchable_labels.join(".");
    if (!p.unicode_labels.length || !p.label || p.is_ip || !p.suffix) p.unicode_label = p.label;
    else {
      const idx = p.labels.length - (p.suffix.split(".").length - 1) - 2;
      p.unicode_label = idx >= 0 && idx < p.unicode_labels.length ? p.unicode_labels[idx] : p.label;
    }
    return p;
  }
  function isSubdomainOf(hostname, parent) {
    const h = normalizeDomain(hostname), pr = normalizeDomain(parent);
    if (!h || !pr) return false;
    return h === pr || h.endsWith("." + pr);
  }
  function matchesAny(hostname, parents) {
    for (const p of parents || []) if (isSubdomainOf(hostname, p)) return p;
    return null;
  }
  function scriptOf(ch) {
    if (!ch) return "UNKNOWN";
    if (/[0-9]/.test(ch) || "-_.".includes(ch)) return "COMMON";
    if (/\p{Script=Latin}/u.test(ch)) return "LATIN";
    if (/\p{Script=Cyrillic}/u.test(ch)) return "CYRILLIC";
    if (/\p{Script=Greek}/u.test(ch)) return "GREEK";
    if (/\p{Script=Arabic}/u.test(ch)) return "ARABIC";
    if (/\p{Script=Armenian}/u.test(ch)) return "ARMENIAN";
    if (/\p{Script=Hebrew}/u.test(ch)) return "HEBREW";
    if (/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u.test(ch)) return "CJK";
    if (/\p{Script=Common}|\p{P}|\p{S}/u.test(ch)) return "COMMON";
    if (/\p{Script=Inherited}/u.test(ch)) return "COMMON";
    return "OTHER";
  }
  function scriptsIn(text) {
    const s = new Set();
    for (const ch of text) { const sc = scriptOf(ch); if (sc !== "COMMON") s.add(sc); }
    return s;
  }
  function isMixedScript(text) { return scriptsIn(text).size > 1; }
  function containsArabic(text) { return ARABIC_RANGE.test(text || ""); }
  function normalizeArabic(text) {
    if (!text) return "";
    let out = text.replace(ARABIC_DIACRITICS, "");
    out = Array.from(out, (c) => ARABIC_FOLD[c] || c).join("");
    return out.trim();
  }
  function confusableSkeleton(text) {
    if (!text) return "";
    let out = "";
    for (const ch of text.toLowerCase()) {
      if (CONFUSABLES[ch] !== undefined) { out += CONFUSABLES[ch]; continue; }
      if (isAscii(ch)) { out += ch; continue; }
      const dec = ch.normalize("NFKD");
      let ascii = "";
      for (const c of dec) if (isAscii(c) && /[a-z0-9]/i.test(c) && !/\p{M}/u.test(c)) ascii += c;
      out += ascii ? ascii.toLowerCase() : ch;
    }
    return out;
  }
  function leetNormalize(text) {
    if (!text) return "";
    let mapped = Array.from(text.toLowerCase(), (c) => LEET_MAP[c] !== undefined ? LEET_MAP[c] : c).join("");
    for (const [seq, repl] of VISUAL_SEQUENCES) mapped = mapped.split(seq).join(repl);
    return mapped;
  }
  function brandSkeleton(text) { return leetNormalize(confusableSkeleton(text)).replace(/[-_]/g, ""); }
  function shannonEntropy(text) {
    if (!text) return 0;
    const f = {};
    for (const c of text) f[c] = (f[c] || 0) + 1;
    const n = Array.from(text).length;
    let h = 0;
    for (const k in f) { const p = f[k] / n; h -= p * Math.log2(p); }
    return h;
  }
  function levenshtein(s1, s2, maxDistance) {
    if (s1 === s2) return 0;
    if (s1.length < s2.length) { const t = s1; s1 = s2; s2 = t; }
    if (!s2.length) return s1.length;
    if (maxDistance !== undefined && maxDistance !== null && s1.length - s2.length > maxDistance) return maxDistance + 1;
    let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
    for (let i = 1; i <= s1.length; i++) {
      const curr = [i];
      let rowMin = i;
      for (let j = 1; j <= s2.length; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        const val = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        curr.push(val);
        if (val < rowMin) rowMin = val;
      }
      if (maxDistance !== undefined && maxDistance !== null && rowMin > maxDistance) return maxDistance + 1;
      prev = curr;
    }
    return prev[prev.length - 1];
  }
  function similarity(s1, s2) {
    const longest = Math.max(s1.length, s2.length);
    return longest === 0 ? 1 : 1 - levenshtein(s1, s2) / longest;
  }
  function typoThreshold(len) { return len <= 4 ? 1 : len <= 8 ? 2 : 3; }
  function tokensOf(label) { return label.toLowerCase().split(/[-_\d]+/).filter(Boolean); }
  function tldRisk(suffix) {
    if (!suffix) return "none";
    const last = suffix.split(".").pop().toLowerCase();
    return HIGH_TLDS.has(last) ? "high" : MEDIUM_TLDS.has(last) ? "medium" : "none";
  }
  function scoreToLevel(score) { return score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "clean"; }
  const LEVEL_ORDER = ["clean", "low", "medium", "high", "critical"];
  function bumpLevel(level, steps) {
    const idx = Math.max(0, LEVEL_ORDER.indexOf(level));
    return LEVEL_ORDER[Math.min(LEVEL_ORDER.length - 1, idx + (steps || 1))];
  }

  // ------------------------------------------------------------------ //
  // Squatting technique detection
  // ------------------------------------------------------------------ //
  const VOWELS = "aeiou";
  const WEAK_SHORT = new Set(["replacement", "keyboard_typo", "omission", "insertion", "vowel_swap", "bitsquat"]);
  const KEYBOARD = D.keyboard_adjacent;

  function decompose(remainder, vocabulary) {
    vocabulary = vocabulary || VOCABULARY;
    remainder = remainder.replace(/^[-_]+|[-_]+$/g, "");
    if (!remainder) return [];
    if (/^\d+$/.test(remainder)) return [remainder];
    const n = remainder.length;
    const best = new Array(n + 1).fill(null);
    best[0] = [];
    for (let i = 1; i <= n; i++) {
      for (let j = Math.max(0, i - 20); j < i; j++) {
        if (best[j] === null) continue;
        let piece = remainder.slice(j, i);
        if (piece === "-" || piece === "_") { if (best[i] === null) best[i] = best[j].slice(); continue; }
        piece = piece.replace(/^[-_]+|[-_]+$/g, "");
        if (piece && (vocabulary.has(piece) || /^\d+$/.test(piece))) {
          const cand = best[j].concat([piece]);
          if (best[i] === null || cand.length < best[i].length) best[i] = cand;
        }
      }
    }
    return best[n];
  }
  function classifySingleEdit(label, brand) {
    if (label.length === brand.length - 1) return "omission";
    if (label.length === brand.length + 1) {
      for (let i = 0; i < label.length; i++) {
        if (label.slice(0, i) + label.slice(i + 1) === brand) {
          const prev = i > 0 ? label[i - 1] : "", next = i + 1 < label.length ? label[i + 1] : "";
          return label[i] === prev || label[i] === next ? "repetition" : "insertion";
        }
      }
      return "insertion";
    }
    if (label.length === brand.length) {
      const diffs = [];
      for (let i = 0; i < label.length; i++) if (label[i] !== brand[i]) diffs.push([label[i], brand[i]]);
      if (diffs.length === 1) {
        const [a, b] = diffs[0];
        if (VOWELS.includes(a) && VOWELS.includes(b)) return "vowel_swap";
        const xor = a.charCodeAt(0) ^ b.charCodeAt(0);
        if (xor && (xor & (xor - 1)) === 0) return "bitsquat";
        if ((KEYBOARD[b] || "").includes(a)) return "keyboard_typo";
        return "replacement";
      }
    }
    return "replacement";
  }
  function isTransposition(label, brand) {
    if (label.length !== brand.length) return false;
    const diffs = [];
    for (let i = 0; i < label.length; i++) if (label[i] !== brand[i]) diffs.push(i);
    return diffs.length === 2 && diffs[1] === diffs[0] + 1 && label[diffs[0]] === brand[diffs[1]] && label[diffs[1]] === brand[diffs[0]];
  }
  function typoOf(text, brand, threshold) {
    if (text === brand) return null;
    if (isTransposition(text, brand)) return [2, "transposition"];
    const distance = levenshtein(text, brand, threshold);
    if (distance > 0 && distance <= threshold && Math.abs(text.length - brand.length) <= 2) {
      if (distance === 1) return [distance, classifySingleEdit(text, brand)];
      return [distance, text.length === brand.length ? "replacement" : "insertion"];
    }
    return null;
  }
  function emptyInfo(matched) {
    return { techniques: [], similarity: matched ? 1 : 0, distance: matched ? 0 : null, weak: false, combo_keywords: [] };
  }
  function detectTechniques(label, brandLabel, unicodeLabel, maxDistance, allowTypo, excludeTokens) {
    if (allowTypo === undefined) allowTypo = true;
    const raw = label.toLowerCase(), brand = brandLabel.toLowerCase();
    const display = (unicodeLabel || raw).toLowerCase();
    if (!raw || !brand || raw === brand) return emptyInfo(raw === brand);
    const techniques = [];
    let comboKeywords = [], weak = false, distance = null;
    const folded = confusableSkeleton(display);
    const hyphenated = leetNormalize(folded);
    const skeleton = hyphenated.replace(/[-_]/g, "");
    const isHomoglyph = display !== folded;
    if (isHomoglyph && folded.replace(/-/g, "") === brand) techniques.push("homoglyph");
    else if (skeleton === brand && /\d/.test(raw)) techniques.push("leet_substitution");
    else if (skeleton === brand && raw.includes("-")) techniques.push("hyphenation");

    const excluded = excludeTokens || new Set();
    const vocabulary = excluded.size ? new Set([...VOCABULARY, ...excluded]) : VOCABULARY;
    const plain = folded.replace(/[-_]/g, "");
    if (!techniques.length && (plain.includes(brand) || skeleton.includes(brand))) {
      const tokens = tokensOf(folded);
      const restCandidates = [];
      if (folded.includes(brand)) restCandidates.push(folded.replace(brand, ""));
      else if (plain.includes(brand)) restCandidates.push(plain.replace(brand, ""));
      if (hyphenated.includes(brand)) restCandidates.push(hyphenated.replace(brand, ""));
      else if (skeleton.includes(brand)) restCandidates.push(skeleton.replace(brand, ""));
      let decomposed = null;
      for (const rest of restCandidates) {
        const parts = [];
        let ok = true;
        for (const other of rest.split(/[-_]+/).filter(Boolean)) {
          const sub = decompose(other, vocabulary);
          if (sub === null) { ok = false; break; }
          parts.push(...sub);
        }
        if (ok) { decomposed = parts; break; }
      }
      const words = (decomposed || []).filter((p) => !/^\d+$/.test(p));
      if (decomposed !== null && words.length) { techniques.push("combo_squat"); comboKeywords = words; }
      else if (decomposed !== null && decomposed.length) techniques.push("addition");
      else if (tokens.includes(brand) || brand.length >= 5) techniques.push("brand_embedding");
      if (techniques.length && isHomoglyph) techniques.push("homoglyph");
    }
    if (!techniques.length && allowTypo && skeleton.length >= 3) {
      if (brand.includes(skeleton) && skeleton.length < brand.length) return emptyInfo(false);
      let threshold = typoThreshold(brand.length);
      if (maxDistance !== undefined && maxDistance !== null) threshold = Math.min(threshold, maxDistance);
      let typo = excluded.has(skeleton) ? null : typoOf(skeleton, brand, threshold);
      if (typo) {
        distance = typo[0];
        techniques.push("typosquat", typo[1]);
        weak = brand.length <= 4 && WEAK_SHORT.has(typo[1]);
      } else {
        const toks = tokensOf(hyphenated).filter((t) => t.length >= 3);
        for (const tok of toks) {
          if (tok === skeleton || excluded.has(tok)) continue;
          typo = typoOf(tok, brand, threshold);
          if (!typo) continue;
          const others = toks.filter((t) => t !== tok);
          if (others.length && others.every((o) => decompose(o, vocabulary) !== null)) {
            distance = typo[0];
            techniques.push("typosquat", typo[1], "combo_squat");
            comboKeywords = others.filter((o) => !/^\d+$/.test(o));
            weak = brand.length <= 4 && WEAK_SHORT.has(typo[1]);
            break;
          }
        }
      }
      if (techniques.length && isHomoglyph) techniques.push("homoglyph");
    }
    return { techniques, similarity: similarity(skeleton, brand), distance, weak, combo_keywords: comboKeywords };
  }
  function contextSignals(parsed, brandLabel) {
    const signals = new Set();
    for (const lbl of parsed.searchable_labels)
      for (const tok of tokensOf(leetNormalize(lbl)))
        if (tok !== brandLabel && VOCABULARY.has(tok) && tok.length > 1) signals.add(tok);
    const risk = tldRisk(parsed.suffix);
    if (risk !== "none") signals.add("tld:" + risk);
    if (parsed.hosting_platform) signals.add("free_hosting");
    return signals;
  }

  // ------------------------------------------------------------------ //
  // Domain analyzer
  // ------------------------------------------------------------------ //
  class DomainAnalyzer {
    constructor(opts) {
      opts = opts || {};
      this.protectedBrands = (opts.protectedBrands || D.protected_brands).slice();
      this.allowlist = (opts.allowlist || []).map((x) => x.toLowerCase());
      this.legitimateDomains = (opts.legitimateDomains || []).map((x) => x.toLowerCase());
      this.maxDistance = opts.maxDistance || 3;
      this.maxPermutations = opts.maxPermutations || 2000;
      this._cache = {};
    }
    addAllowlist(d) { if (d && !this.allowlist.includes(d)) this.allowlist.push(d); }
    removeAllowlist(d) { this.allowlist = this.allowlist.filter((x) => x !== d); }
    _brand(b) { return this._cache[b] || (this._cache[b] = parseDomain(b)); }
    _knownLabels() { return new Set(this.protectedBrands.map((b) => this._brand(b).label)); }
    isLegitimate(hostname) {
      return !!(matchesAny(hostname, this.protectedBrands) || matchesAny(hostname, this.legitimateDomains) || matchesAny(hostname, this.allowlist));
    }
    analyze(domain) {
      const parsed = parseDomain(domain);
      if (!parsed.valid || parsed.is_ip || !parsed.label) return [];
      if (this.isLegitimate(parsed.hostname)) return [];
      const known = this._knownLabels();
      const results = [];
      for (const brand of this.protectedBrands) {
        const r = this._against(parsed, brand, known);
        if (r) results.push(r);
      }
      results.sort((a, b) => b.confidence - a.confidence || b.similarity - a.similarity || (a.target < b.target ? -1 : a.target > b.target ? 1 : 0));
      return results;
    }
    _against(parsed, brand, known) {
      const bp = this._brand(brand), brandLabel = bp.label;
      if (brandLabel.length < 3) return null;
      let attacks = [], details = {}, matchedLabel = parsed.label, sim = 0, weak = false;
      if (parsed.label === brandLabel) {
        attacks.push("tld_swap"); details.original_suffix = bp.suffix; details.swapped_suffix = parsed.suffix; sim = 1;
      } else {
        const excl = new Set(known); excl.delete(brandLabel);
        const info = detectTechniques(parsed.label, brandLabel, parsed.unicode_label, this.maxDistance, true, excl);
        if (info.techniques.length) {
          attacks.push(...info.techniques); sim = info.similarity; weak = info.weak;
          if (info.distance !== null) details.levenshtein_distance = info.distance;
          if (info.combo_keywords.length) details.combo_keywords = info.combo_keywords;
        }
      }
      for (const sub of parsed.subdomain_labels) {
        if (sub === brandLabel || brandSkeleton(sub) === brandLabel) {
          if (!attacks.length) { matchedLabel = sub; sim = Math.max(sim, 0.9); }
          attacks.push("subdomain_abuse"); details.abused_subdomain = sub; break;
        }
        const si = detectTechniques(sub, brandLabel, undefined, undefined, false);
        if (si.techniques.includes("combo_squat") || si.techniques.includes("homoglyph")) {
          if (!attacks.length) { matchedLabel = sub; sim = Math.max(sim, si.similarity); }
          attacks.push("subdomain_abuse"); details.abused_subdomain = sub; break;
        }
      }
      if (parsed.subdomain && parsed.subdomain.includes(bp.hostname)) details.contains_brand_hostname = true;
      if (!attacks.length) return null;
      const signals = contextSignals(parsed, brandLabel);
      if (weak && !signals.size) return null;
      if (signals.size) details.context = Array.from(signals).sort();
      attacks = Array.from(new Set(attacks));
      const [risk, confidence] = DomainAnalyzer.score(attacks, sim, signals, weak);
      return {
        target: brand, suspicious_domain: parsed.original.trim() || parsed.hostname, attack_types: attacks,
        similarity: Math.round(sim * 10000) / 10000, risk_level: risk, confidence, matched_label: matchedLabel, details,
        timestamp: new Date().toISOString(),
      };
    }
    static score(attacks, sim, signals, weak) {
      const strong = new Set(["homoglyph", "leet_substitution", "combo_squat", "tld_swap"]);
      let confidence;
      if (attacks.some((a) => strong.has(a))) confidence = 0.8;
      else if (attacks.includes("subdomain_abuse")) confidence = 0.75;
      else if (attacks.includes("hyphenation")) confidence = 0.7;
      else if (attacks.includes("typosquat")) confidence = weak ? 0.45 : 0.65;
      else if (attacks.includes("brand_embedding") || attacks.includes("addition")) confidence = 0.5;
      else confidence = 0.35;
      confidence += 0.05 * Math.min(signals.size, 3);
      if (sim >= 0.85) confidence += 0.05;
      confidence = Math.min(confidence, 0.99);
      const riskyTld = Array.from(signals).some((s) => s.startsWith("tld:"));
      const hosted = signals.has("free_hosting");
      let level;
      if (attacks.includes("homoglyph") || attacks.includes("leet_substitution")) level = "critical";
      else if (attacks.includes("combo_squat") && (riskyTld || hosted)) level = "critical";
      else if (attacks.includes("combo_squat") || attacks.includes("subdomain_abuse") || attacks.includes("tld_swap")) level = "high";
      else if (attacks.includes("hyphenation")) level = riskyTld ? "high" : "medium";
      else if (attacks.includes("typosquat") && !weak) level = (sim >= 0.8 && signals.size) || riskyTld ? "high" : "medium";
      else if (attacks.includes("brand_embedding") || attacks.includes("addition") || weak) level = signals.size ? "medium" : "low";
      else level = "medium";
      return [level, Math.round(confidence * 1000) / 1000];
    }
    permutationLabels(brand) {
      const base = parseDomain(brand).label || brand.split(".")[0].toLowerCase();
      const seen = new Set(), out = [];
      const add = (label, technique) => {
        if (!label || label === base || seen.has(label)) return;
        if (label.startsWith("-") || label.endsWith("-")) return;
        seen.add(label); out.push({ label, technique });
      };
      const n = base.length;
      for (let i = 0; i < n; i++) add(base.slice(0, i) + base.slice(i + 1), "omission");
      for (let i = 0; i < n - 1; i++) { const c = base.split(""); [c[i], c[i + 1]] = [c[i + 1], c[i]]; add(c.join(""), "transposition"); }
      for (let i = 0; i < n; i++) add(base.slice(0, i + 1) + base[i] + base.slice(i + 1), "repetition");
      for (let i = 0; i < n; i++) for (const adj of KEYBOARD[base[i]] || "") add(base.slice(0, i) + adj + base.slice(i + 1), "replacement");
      for (let i = 0; i <= n; i++) {
        const nb = new Set();
        if (i > 0) for (const c of KEYBOARD[base[i - 1]] || "") nb.add(c);
        if (i < n) for (const c of KEYBOARD[base[i]] || "") nb.add(c);
        for (const adj of Array.from(nb).sort()) add(base.slice(0, i) + adj + base.slice(i), "insertion");
      }
      for (let i = 0; i < n; i++) if (VOWELS.includes(base[i])) for (const v of VOWELS) if (v !== base[i]) add(base.slice(0, i) + v + base.slice(i + 1), "vowel_swap");
      for (let i = 0; i < n; i++) {
        const code = base.charCodeAt(i);
        for (let bit = 0; bit < 7; bit++) {
          const f = String.fromCharCode(code ^ (1 << bit));
          if (/^[0-9]$/.test(f) || /^[a-z]$/.test(f)) add(base.slice(0, i) + f + base.slice(i + 1), "bitsquat");
        }
      }
      for (let i = 1; i < n; i++) add(base.slice(0, i) + "-" + base.slice(i), "hyphenation");
      for (let i = 0; i < n; i++) for (const sub of D.leet_generation[base[i]] || []) add(base.slice(0, i) + sub + base.slice(i + 1), "leet_substitution");
      for (let i = 0; i < n; i++) for (const g of (D.homoglyphs[base[i]] || []).slice(0, 3)) add(base.slice(0, i) + g + base.slice(i + 1), "homoglyph");
      for (const extra of ["s", "1", "2", "kw", "q8", "online", "bank", "www"]) { add(base + extra, "addition"); if (extra === "www") add("www" + base, "addition"); }
      for (const kw of D.generation_combos) { add(base + "-" + kw, "combo_squat"); add(base + kw, "combo_squat"); add(kw + "-" + base, "combo_squat"); add(kw + base, "combo_squat"); }
      return out;
    }
    generatePermutations(brand) { return Array.from(new Set(this.permutationLabels(brand).map((p) => p.label))).sort(); }
    generatePermutationsDetailed(brand, opts) {
      opts = opts || {};
      const pb = parseDomain(brand);
      const base = pb.label || brand.split(".")[0].toLowerCase();
      const own = pb.suffix || "com";
      let suffixes = (opts.tlds || [own]).map((s) => String(s).replace(/^\.+|\.+$/g, "").toLowerCase()).filter(Boolean);
      if (!suffixes.length) suffixes = [own];
      const limit = opts.maxResults || this.maxPermutations;
      let labels = this.permutationLabels(brand);
      if (opts.includeCombos === false) labels = labels.filter((p) => p.technique !== "combo_squat" && p.technique !== "addition");
      if (opts.includeHomoglyphs === false) labels = labels.filter((p) => p.technique !== "homoglyph");
      const out = [], seen = new Set();
      for (const suffix of suffixes) if (suffix !== own) { const d = base + "." + suffix; if (!seen.has(d)) { seen.add(d); out.push({ domain: d, label: base, technique: "tld_swap", tld: suffix }); } }
      for (const suffix of suffixes) for (const perm of labels) {
        let label = perm.label;
        if (!isAscii(label)) { try { label = "xn--" + punycodeEncode(label); } catch (e) { continue; } }
        const d = label + "." + suffix;
        if (seen.has(d) || d === pb.hostname) continue;
        seen.add(d); out.push({ domain: d, label, technique: perm.technique, tld: suffix });
        if (out.length >= limit) return out;
      }
      return out;
    }
  }

  // ------------------------------------------------------------------ //
  // Brand monitor
  // ------------------------------------------------------------------ //
  const SEVERITY_SCORE = { critical: 90, high: 70, medium: 50, low: 30 };
  const MIN_PHRASE_LEN = 8;
  class BrandMonitor {
    constructor(opts) {
      opts = opts || {};
      this.brands = (opts.brands || D.brands).map((b) => Object.assign({}, b));
      this.allowlist = (opts.allowlist || []).map((x) => x.toLowerCase());
      this.dedupeWindow = opts.dedupeWindowSeconds === undefined ? 86400 : opts.dedupeWindowSeconds;
      this._now = opts.now || (() => Date.now() / 1000);
      this._recent = new Map();
      this._counter = 0;
      this.alerts = [];
    }
    addAllowlist(d) { d = d.toLowerCase(); if (d && !this.allowlist.includes(d)) this.allowlist.push(d); }
    removeAllowlist(d) { this.allowlist = this.allowlist.filter((x) => x !== d.toLowerCase()); }
    protectedDomains() { const out = []; for (const b of this.brands) for (const d of b.domains) if (!out.includes(d)) out.push(d); return out; }
    static legit(brand, hostname) { return brand.domains.some((d) => isSubdomainOf(hostname, d)); }
    checkDomain(domain, source, record) {
      source = source || "scan"; if (record === undefined) record = true;
      const parsed = parseDomain(domain);
      if (!parsed.valid || parsed.is_ip || !parsed.label) return [];
      if (matchesAny(parsed.hostname, this.allowlist)) return [];
      if (this.brands.some((b) => BrandMonitor.legit(b, parsed.hostname))) return [];
      const known = new Set();
      for (const b of this.brands) for (const l of b.primary_labels) known.add(l);
      let matches = [];
      for (const b of this.brands) { const c = this._matchBrand(parsed, b, known); if (c) matches.push([b, c]); }
      if (!matches.length) return [];
      const top = Math.max(...matches.map(([, c]) => c[0]));
      if (top >= 85) matches = matches.filter(([, c]) => c[0] >= 85);
      const alerts = [];
      for (const [b, [, type, severity, evidence]] of matches) {
        if (record && this._dup(b.name, parsed.hostname)) continue;
        const a = this._build(parsed, b, type, severity, evidence, source);
        alerts.push(a);
        if (record) this.alerts.push(a);
      }
      return alerts;
    }
    _dup(name, host) {
      if (this.dedupeWindow <= 0) return false;
      const key = name + "|" + host, now = this._now(), last = this._recent.get(key);
      if (last !== undefined && now - last < this.dedupeWindow) return true;
      this._recent.set(key, now);
      return false;
    }
    _matchBrand(parsed, brand, known) {
      const cands = [], risky = tldRisk(parsed.suffix), pt = BrandMonitor.phishingTokens(parsed);
      const primary = new Set(brand.primary_labels);
      const excluded = new Set(Array.from(known).filter((l) => !primary.has(l)));
      const byLen = (a, b) => b.length - a.length;
      for (const bl of brand.primary_labels.slice().sort(byLen)) { const f = this._matchLabel(parsed, brand, bl, risky, pt, true, excluded); if (f) cands.push(f); }
      for (const bl of brand.alias_labels.slice().sort(byLen)) { const f = this._matchLabel(parsed, brand, bl, risky, pt, false, excluded); if (f) cands.push(f); }
      const compact = brandSkeleton(parsed.searchable_text.replace(/\./g, ""));
      const tokens = new Set();
      for (const l of parsed.searchable_labels) for (const t of tokensOf(l)) tokens.add(t);
      for (const words of brand.phrases) {
        const joined = words.join("");
        const significant = words.filter((w) => w.length > 2);
        const phraseHit = joined.length >= MIN_PHRASE_LEN && compact.includes(joined);
        const tokenHit = significant.length >= 2 && significant.every((w) => tokens.has(w));
        if (phraseHit || tokenHit) { cands.push([40, "brand_keyword_abuse", BrandMonitor.severityFor("medium", risky, pt, 0), { matched_keyword: words.join(" ") }]); break; }
      }
      if (parsed.is_idn && brand.arabic_keywords.length) {
        const ut = normalizeArabic(parsed.unicode_hostname);
        if (containsArabic(ut)) {
          for (let i = 0; i < brand.arabic_keywords.length; i++) {
            if (ut.includes(brand.arabic_normalized[i])) {
              cands.push([70, "arabic_brand_keyword", BrandMonitor.severityFor("high", risky, pt, 0), { matched_keyword: brand.arabic_keywords[i], unicode_hostname: parsed.unicode_hostname }]);
              break;
            }
          }
        }
      }
      if (!cands.length) return null;
      cands.sort((a, b) => b[0] - a[0]);
      const [rank, type, severity, evidence] = cands[0];
      if (risky !== "none") evidence.tld_risk = risky;
      if (pt.size) evidence.phishing_keywords = Array.from(pt).sort();
      if (parsed.hosting_platform) evidence.hosting_platform = parsed.hosting_platform;
      return [rank, type, severity, evidence];
    }
    _matchLabel(parsed, brand, bl, risky, pt, allowTypo, excluded) {
      const base = SEVERITY_SCORE[brand.priority] ? brand.priority : "high";
      const sev = (lvl, extra) => BrandMonitor.severityFor(lvl, risky, pt, extra || 0);
      if (parsed.label === bl) return [90, "domain_squat", sev(base), { technique: "tld_swap", matched_label: parsed.label }];
      const info = detectTechniques(parsed.label, bl, parsed.unicode_label, undefined, allowTypo, excluded);
      let techniques = info.techniques.slice();
      if (techniques.length && info.weak && !contextSignals(parsed, bl).size) techniques = [];
      if (techniques.length) {
        const ev = { technique: techniques[0], techniques, matched_label: parsed.label, similarity: Math.round(info.similarity * 1000) / 1000 };
        if (info.combo_keywords.length) ev.combo_keywords = info.combo_keywords;
        if (parsed.is_idn) ev.unicode_label = parsed.unicode_label;
        if (techniques.includes("homoglyph")) return [95, "idn_homograph", "critical", ev];
        if (techniques.includes("leet_substitution")) return [88, "domain_squat", sev(base, 1), ev];
        if (techniques.includes("combo_squat")) return [85, "combo_squat", sev(base), ev];
        if (techniques.includes("typosquat") || techniques.includes("hyphenation")) {
          let level = base === "critical" ? "high" : "medium";
          if (info.weak) level = "medium";
          return [80, techniques.includes("hyphenation") ? "domain_squat" : "typosquat", sev(level), ev];
        }
        if (techniques.includes("addition")) return [60, "domain_squat", sev("medium"), ev];
        if (techniques.includes("brand_embedding")) return [55, "brand_keyword_abuse", sev(base === "critical" || base === "high" ? "medium" : "low"), ev];
      }
      for (const sub of parsed.subdomain_labels) {
        if (sub === bl || brandSkeleton(sub) === bl) return [75, "subdomain_abuse", sev(base === "critical" ? "critical" : "high"), { abused_subdomain: sub, matched_label: bl }];
        const si = detectTechniques(sub, bl, undefined, undefined, false);
        if (si.techniques.includes("combo_squat")) return [72, "subdomain_abuse", sev("high"), { abused_subdomain: sub, matched_label: bl, combo_keywords: si.combo_keywords }];
      }
      return null;
    }
    static phishingTokens(parsed) {
      const found = new Set();
      for (const lbl of parsed.searchable_labels) {
        for (const tok of tokensOf(lbl)) if (PHISHING_KEYWORDS.has(tok)) found.add(tok);
        for (const kw of PHISHING_KEYWORDS) if (kw.length >= 5 && lbl.includes(kw)) found.add(kw);
      }
      return found;
    }
    static severityFor(base, risky, pt, extra) {
      const level = SEVERITY_SCORE[base] ? base : "medium";
      let steps = extra || 0;
      if (risky === "high") steps += 1;
      if (pt.size) steps += 1;
      return steps ? bumpLevel(level, steps) : level;
    }
    _build(parsed, brand, type, severity, evidence, source) {
      this._counter += 1;
      const id = "BA-" + Math.floor(this._now() * 1000).toString(16).slice(-6) + this._counter.toString(16).padStart(3, "0");
      const desc = {
        domain_squat: `Domain squatting of ${brand.name}: ${parsed.hostname}`,
        idn_homograph: `IDN homograph attack impersonating ${brand.name}: ${parsed.unicode_hostname} (${parsed.hostname})`,
        combo_squat: `Combo-squat targeting ${brand.name}: ${parsed.hostname}`,
        typosquat: `Typosquat of ${brand.name}: ${parsed.hostname}`,
        subdomain_abuse: `${brand.name} label abused in subdomain: ${parsed.hostname}`,
        brand_keyword_abuse: `Brand keyword for ${brand.name} found in domain: ${parsed.hostname}`,
        arabic_brand_keyword: `Arabic brand keyword for ${brand.name} in IDN domain: ${parsed.unicode_hostname}`,
      };
      return {
        alert_id: id, brand_name: brand.name, brand_short: brand.short_name || brand.name, alert_type: type, severity,
        description: desc[type] || `Brand impersonation of ${brand.name}`,
        evidence: Object.assign({ suspicious_domain: parsed.hostname, registrable_domain: parsed.registrable, protected_domains: brand.domains.slice(), brand: brand.name, source }, evidence),
        detected_at: new Date().toISOString(), status: "open", assignee: null, risk_score: SEVERITY_SCORE[severity] || 50, domain: parsed.hostname,
      };
    }
  }

  // ------------------------------------------------------------------ //
  // Phishing detector
  // ------------------------------------------------------------------ //
  const CAPS = { keyword_abuse: 36, brand_impersonation: 55, structural_anomaly: 30, idn_attack: 55 };
  function ind(type, detail, weight, extra) { return Object.assign({ type, detail, weight: Math.round(weight * 10) / 10 }, extra || {}); }

  class PhishingDetector {
    constructor(opts) {
      opts = opts || {};
      this.brands = opts.brands || D.brands;
      this.allowlist = new Set((opts.allowlist || []).map((x) => x.toLowerCase()));
      this.falsePositives = new Set();
      this.detectionCount = 0;
      const protectedBrands = opts.protectedBrands || D.protected_brands;
      this.protectedDomains = [];
      for (const b of this.brands) for (const d of b.domains) if (!this.protectedDomains.includes(d)) this.protectedDomains.push(d.toLowerCase());
      for (const d of protectedBrands) if (!this.protectedDomains.includes(d.toLowerCase())) this.protectedDomains.push(d.toLowerCase());
      this.brandTokens = new Map();
      const setdefault = (k, v) => { if (!this.brandTokens.has(k)) this.brandTokens.set(k, v); };
      for (const b of this.brands) {
        const name = b.short_name || b.name;
        for (const l of b.primary_labels) setdefault(l, name);
        for (const l of b.alias_labels) setdefault(l, name);
      }
      for (const d of this.protectedDomains) { const l = parseDomain(d).label; if (l.length >= 3) setdefault(l, l.toUpperCase()); }
      for (const t of (D.brand_tokens || D.__brand_tokens || [])) setdefault(t, t.toUpperCase());
      for (const t of D.global_brands) setdefault(t, t.charAt(0).toUpperCase() + t.slice(1));
      this.primaryTokens = new Set();
      for (const b of this.brands) for (const l of b.primary_labels) this.primaryTokens.add(l);
      for (const t of D.global_brands) if (t.length >= 5) this.primaryTokens.add(t);
      this.knownTokens = new Set(this.brandTokens.keys());
      this.monitoredPrimary = new Set();
      this.brandPriority = new Map();
      const pset = (k, v) => { if (!this.brandPriority.has(k)) this.brandPriority.set(k, v); };
      for (const b of this.brands) {
        for (const l of b.primary_labels) { this.monitoredPrimary.add(l); pset(l, b.priority || "medium"); }
        for (const l of b.alias_labels) pset(l, b.priority || "medium");
      }
      for (const d of protectedBrands) { const l = parseDomain(d).label; if (l.length >= 3) { this.monitoredPrimary.add(l); pset(l, "high"); } }
      this.arabicBrand = [];
      for (const b of this.brands) {
        const name = b.short_name || b.name;
        b.arabic_normalized.forEach((k) => this.arabicBrand.push([k, name, b.priority || "medium"]));
      }
    }
    markFalsePositive(d) { this.falsePositives.add(parseDomain(d).hostname); }
    analyze(domain, context) {
      this.detectionCount += 1;
      context = context || {};
      const parsed = parseDomain(domain);
      if (!parsed.hostname) return this._clean(domain, parsed, [], "Empty or invalid input.");
      if (this.falsePositives.has(parsed.hostname) || matchesAny(parsed.hostname, this.falsePositives))
        return this._clean(domain, parsed, [ind("false_positive_override", "Marked as false positive", 0)], "Marked as false positive.");
      const allow = matchesAny(parsed.hostname, this.allowlist);
      if (allow) return this._clean(domain, parsed, [ind("allowlisted", "Allowlisted via " + allow, 0)], "Domain is allowlisted.");
      const brandHit = matchesAny(parsed.hostname, this.protectedDomains);
      if (brandHit) return this._clean(domain, parsed, [ind("protected_brand_domain", "Official domain of " + brandHit, 0)], "Legitimate protected-brand infrastructure.");

      const indicators = [], categories = new Set();
      let matched = [], total = 0;
      const add = (score, cat, inds) => { if (!inds.length) return; total += score; indicators.push(...inds); if (cat) categories.add(cat); };
      if (parsed.is_ip) {
        add(25, "structural_anomaly", [ind("ip_address_host", "Raw IP address used as host", 25)]);
        add(...this._keywords(parsed));
        return this._finish(domain, parsed, indicators, categories, matched, total);
      }
      if (!parsed.valid) add(8, "structural_anomaly", [ind("invalid_hostname", "Hostname contains invalid characters", 8)]);
      add(...this._keywords(parsed));
      const br = this._brands(parsed);
      if (br.inds.length) { total += br.score; indicators.push(...br.inds); br.cats.forEach((c) => categories.add(c)); matched = br.brands; }
      add(...PhishingDetector._tld(parsed, br.inds.length > 0));
      add(...PhishingDetector._structure(parsed));
      add(...PhishingDetector._entropy(parsed));
      const idn = this._idn(parsed);
      if (idn.inds.length) { total += idn.score; indicators.push(...idn.inds); idn.cats.forEach((c) => categories.add(c)); for (const b of idn.brands) if (!matched.includes(b)) matched.push(b); }
      add(...PhishingDetector._hosting(parsed, br.inds.length > 0));
      add(...PhishingDetector._context(parsed, context, br.inds.length > 0));
      if (br.inds.length && indicators.some((i) => i.type === "phishing_keyword"))
        add(10, "brand_impersonation", [ind("brand_lure_synergy", "Brand look-alike combined with lure keywords", 10)]);
      return this._finish(domain, parsed, indicators, categories, matched, total);
    }
    _keywords(parsed) {
      const inds = [], seen = new Set();
      let score = 0;
      const labels = parsed.searchable_labels.length ? parsed.searchable_labels : parsed.labels;
      labels.forEach((label, idx) => {
        const inReg = idx === labels.length - 1;
        const found = new Set();
        for (const t of tokensOf(label)) if (PHISHING_KEYWORDS.has(t)) found.add(t);
        for (const kw of PHISHING_KEYWORDS) if (kw.length >= 5 && label.includes(kw)) found.add(kw);
        for (const kw of Array.from(found).sort()) {
          if (seen.has(kw)) continue;
          seen.add(kw);
          const w = inReg ? 12 : 8;
          score += w;
          inds.push(ind("phishing_keyword", `Lure keyword '${kw}' in ${inReg ? "registrable label" : "subdomain"}`, w, { keyword: kw }));
        }
      });
      return [Math.min(score, CAPS.keyword_abuse), "keyword_abuse", inds];
    }
    _brands(parsed) {
      const best = new Map();
      const labels = parsed.searchable_labels;
      if (!labels.length) return { score: 0, inds: [], cats: new Set(), brands: [] };
      const sigCache = new Map();
      labels.forEach((label, idx) => {
        const inReg = idx === labels.length - 1;
        const ul = idx < parsed.unicode_labels.length ? parsed.unicode_labels[idx] : undefined;
        for (const [token, brandName] of this.brandTokens) {
          if (token.length < 3) continue;
          let weight = 0, kind = "", detail = "";
          const cats = new Set();
          if (label === token) {
            if (inReg) {
              if (!this.monitoredPrimary.has(token)) continue;
              weight = 25; kind = "brand_tld_swap"; detail = `Brand label '${token}' (${brandName}) under another suffix`; cats.add("brand_impersonation");
            } else { weight = 25; kind = "brand_in_subdomain"; detail = `Brand label '${token}' (${brandName}) used as a subdomain`; cats.add("brand_impersonation"); cats.add("subdomain_abuse"); }
          } else {
            const excl = new Set(this.knownTokens); excl.delete(token);
            const info = detectTechniques(label, token, ul, undefined, this.primaryTokens.has(token), excl);
            const t = info.techniques;
            if (!t.length) continue;
            if (info.weak) {
              if (!sigCache.has(token)) sigCache.set(token, contextSignals(parsed, token));
              if (!sigCache.get(token).size) continue;
            }
            if (t.includes("homoglyph")) { weight = 40; kind = "idn_homograph"; cats.add("brand_impersonation"); cats.add("idn_attack"); detail = `Homograph of '${token}' (${brandName}): '${ul || label}'`; }
            else if (t.includes("leet_substitution")) { weight = 45; kind = "leet_brand"; cats.add("brand_impersonation"); detail = `Leetspeak disguise of '${token}' (${brandName})`; }
            else if (t.includes("combo_squat")) { weight = inReg ? 35 : 22; kind = "brand_combo"; cats.add("brand_impersonation"); if (!inReg) cats.add("subdomain_abuse"); detail = `Brand '${token}' (${brandName}) combined with ${info.combo_keywords.slice(0, 3).join(", ")}`; }
            else if (t.includes("hyphenation")) { weight = 30; kind = "brand_hyphenation"; cats.add("brand_impersonation"); detail = `Hyphenated brand label '${token}' (${brandName})`; }
            else if (t.includes("typosquat")) { weight = info.weak ? 15 : 35; kind = "brand_typosquat"; cats.add("brand_impersonation"); detail = `Typo of '${token}' (${brandName}): '${label}'`; }
            else if (t.includes("addition") || t.includes("brand_embedding")) { weight = 10; kind = "brand_keyword"; cats.add("brand_impersonation"); detail = `Brand keyword '${token}' (${brandName}) embedded in '${label}'`; }
            else continue;
          }
          if (weight <= 0) continue;
          const cur = best.get(brandName);
          if (!cur || weight > cur[0]) best.set(brandName, [weight, ind(kind, detail, weight, { brand: brandName, label, token }), cats]);
        }
      });
      if (!best.size) return { score: 0, inds: [], cats: new Set(), brands: [] };
      const ranked = Array.from(best.entries()).sort((a, b) => b[1][0] - a[1][0]);
      const [topName, [topW, topInd, topCats]] = ranked[0];
      let score = topW;
      const inds = [topInd], cats = new Set(topCats), brands = [topName];
      const prio = this.brandPriority.get(topInd.token) || "medium";
      const bonus = prio === "critical" ? 10 : prio === "high" ? 5 : 0;
      if (bonus) { score += bonus; inds.push(ind("brand_priority", `${topName} is a ${prio}-priority protected brand`, bonus, { brand: topName })); }
      for (const [name, [w, i, c]] of ranked.slice(1, 3)) { score += Math.min(w, 8); inds.push(i); c.forEach((x) => cats.add(x)); brands.push(name); }
      return { score: Math.min(score, CAPS.brand_impersonation), inds, cats, brands };
    }
    static _tld(parsed, brandMatch) {
      if (parsed.hosting_platform) return [0, "suspicious_tld", []]; // the platform is scored once by _hosting
      const risk = tldRisk(parsed.suffix);
      if (risk === "none") return [0, "suspicious_tld", []];
      let w = risk === "high" ? 20 : 10;
      const inds = [ind(risk + "_risk_tld", `${risk.charAt(0).toUpperCase() + risk.slice(1)}-risk TLD: .${parsed.tld}`, w)];
      if (brandMatch) { inds.push(ind("brand_on_risky_tld", "Brand impersonation on an abuse-prone TLD", 8)); w += 8; }
      return [w, "suspicious_tld", inds];
    }
    static _structure(parsed) {
      const inds = [];
      let score = 0;
      const label = parsed.is_idn ? parsed.unicode_label : parsed.label;
      let depth = parsed.depth;
      if (String(parsed.hostname).split(".")[0] === "www") depth -= 1; // a leading www is a convention, not structure
      if (depth >= 4) { const w = 12 + (depth >= 6 ? 6 : 0); score += w; inds.push(ind("excessive_subdomains", `Hostname has ${depth} labels`, w)); }
      const hyphens = (label.match(/-/g) || []).length;
      if (hyphens >= 3) { score += 10; inds.push(ind("excessive_hyphens", `Label contains ${hyphens} hyphens`, 10)); }
      if (label.length > 25) { score += 8; inds.push(ind("long_domain", `Unusually long label (${label.length} chars)`, 8)); }
      const digits = (label.match(/\d/g) || []).length;
      if (digits >= 5) { score += 8; inds.push(ind("numeric_padding", `Label contains ${digits} digits`, 8)); }
      const tokens = new Set();
      for (const l of parsed.searchable_labels) for (const t of tokensOf(l)) tokens.add(t);
      const embedded = Array.from(tokens).filter((t) => EMBEDDED_TLD_TOKENS.has(t)).sort();
      if (embedded.length && parsed.searchable_labels.length >= 1 && (hyphens || parsed.subdomain)) { score += 10; inds.push(ind("embedded_tld_token", `TLD-like token(s) inside labels: ${embedded.join(", ")}`, 10)); }
      const official = Array.from(tokens).filter((t) => OFFICIAL_TOKENS.has(t)).sort();
      if (official.length && !OFFICIAL_SUFFIXES.has(parsed.suffix) && !parsed.suffix.startsWith("gov.")) {
        score += 12;
        inds.push(ind("fake_official", `Government wording (${official.join(", ")}) outside official registry domains`, 12));
      }
      return [Math.min(score, CAPS.structural_anomaly), "structural_anomaly", inds];
    }
    static _entropy(parsed) {
      const label = parsed.label.replace(/-/g, "");
      if (label.length < 10) return [0, "high_entropy", []];
      const e = shannonEntropy(label);
      const threshold = label.length >= 12 ? 3.8 : 4.0;
      if (e >= threshold) return [12, "high_entropy", [ind("high_entropy", `High entropy label: ${e.toFixed(2)} bits`, 12)]];
      return [0, "high_entropy", []];
    }
    _idn(parsed) {
      if (!parsed.is_idn) return { score: 0, inds: [], cats: new Set(), brands: [] };
      const inds = [ind("punycode_idn", "Internationalized Domain Name (punycode) detected", 12)];
      let score = 12;
      const cats = new Set(["idn_attack"]), brands = [];
      const ul = parsed.unicode_label;
      if (isMixedScript(ul)) { score += 18; inds.push(ind("mixed_script", `Label mixes scripts: ${Array.from(scriptsIn(ul)).sort().join(", ")}`, 18)); }
      if (containsArabic(parsed.unicode_hostname)) {
        const norm = normalizeArabic(parsed.unicode_hostname);
        const lures = Object.entries(D.arabic_lures).filter(([ar]) => norm.includes(ar)).slice(0, 3);
        for (const [ar, en] of lures) { score += 10; inds.push(ind("arabic_lure_keyword", `Arabic lure word '${ar}' (${en})`, 10)); }
        if (lures.length) cats.add("keyword_abuse");
        for (const [ar, name, prio] of this.arabicBrand) {
          if (ar && norm.includes(ar)) {
            const w = 25 + (prio === "critical" ? 10 : prio === "high" ? 5 : 0);
            score += w; cats.add("brand_impersonation"); brands.push(name);
            inds.push(ind("arabic_brand_keyword", `Arabic brand keyword for ${name}`, w, { brand: name }));
            break;
          }
        }
      }
      return { score: Math.min(score, CAPS.idn_attack), inds, cats, brands };
    }
    static _hosting(parsed, brandMatch) {
      if (!parsed.hosting_platform) return [0, "hosting_abuse", []];
      const w = 15 + (brandMatch ? 5 : 0);
      return [w, "hosting_abuse", [ind("free_hosting_platform", `Hosted on shared platform ${parsed.hosting_platform}`, w)]];
    }
    static _context(parsed, context, brandMatch) {
      const inds = [];
      let score = 0;
      const issuer = String(context.issuer || "").toLowerCase();
      if (issuer && brandMatch && D.free_ca_markers.some((m) => issuer.includes(m))) { score += 5; inds.push(ind("free_certificate", "Free CA certificate on a brand look-alike", 5)); }
      if ((context.is_wildcard || parsed.is_wildcard) && brandMatch) { score += 4; inds.push(ind("wildcard_certificate", "Wildcard certificate for a brand look-alike", 4)); }
      return [score, "certificate_context", inds];
    }
    _finish(domain, parsed, indicators, categories, matched, total) {
      const risk = Math.round(Math.min(total, 100) * 10) / 10;
      const level = scoreToLevel(risk);
      return {
        domain, is_phishing: risk >= 50, confidence: Math.min(risk / 100, 0.99), risk_score: risk, risk_level: level,
        indicators, categories: Array.from(categories).sort(), recommendation: PhishingDetector.recommendation(level, matched),
        analyzed_at: new Date().toISOString(), parsed: PhishingDetector.parsedDict(parsed), matched_brands: matched,
        explanation: PhishingDetector.explain(parsed, indicators, matched, level),
      };
    }
    _clean(domain, parsed, indicators, explanation) {
      return {
        domain, is_phishing: false, confidence: 0, risk_score: 0, risk_level: "clean", indicators, categories: [],
        recommendation: PhishingDetector.recommendation("clean", []), analyzed_at: new Date().toISOString(),
        parsed: PhishingDetector.parsedDict(parsed), matched_brands: [], explanation,
      };
    }
    static parsedDict(p) {
      return { hostname: p.hostname, unicode_hostname: p.unicode_hostname, subdomain: p.subdomain, label: p.label, suffix: p.suffix, tld: p.tld, registrable: p.registrable, is_idn: p.is_idn, is_wildcard: p.is_wildcard, is_ip: p.is_ip, hosting_platform: p.hosting_platform, depth: p.depth, valid: p.valid };
    }
    static explain(parsed, indicators, brands, level) {
      if (!indicators.length) return `No phishing indicators found for ${parsed.hostname}.`;
      const top = indicators.slice().sort((a, b) => b.weight - a.weight).slice(0, 3).map((i) => i.detail);
      let prefix = level.toUpperCase() + " risk";
      if (brands.length) prefix += ` (targets ${brands.slice(0, 2).join(", ")})`;
      return prefix + ": " + top.join("; ") + ".";
    }
    static recommendation(level, brands) {
      const note = brands && brands.length ? ` Notify ${brands[0]} security team.` : "";
      const recs = {
        critical: "IMMEDIATE ACTION: Block domain, issue takedown request, notify SOC team." + note,
        high: "HIGH PRIORITY: Add to blocklist, investigate registration details, monitor for active phishing." + note,
        medium: "MONITOR: Add to watchlist, verify with threat intelligence feeds.",
        low: "LOW RISK: Log for reference, no immediate action required.",
        clean: "No threats detected. Domain appears legitimate.",
      };
      return recs[level] || "Review manually.";
    }
  }

  // ------------------------------------------------------------------ //
  // Convenience engine (mirrors src/core/engine.py run_scan)
  // ------------------------------------------------------------------ //
  function createEngine(opts) {
    opts = opts || {};
    const brands = opts.brands || D.brands;
    const monitor = new BrandMonitor({ brands, allowlist: opts.allowlist, dedupeWindowSeconds: opts.dedupeWindowSeconds });
    const analyzer = new DomainAnalyzer({ protectedBrands: opts.protectedBrands, allowlist: opts.allowlist, legitimateDomains: monitor.protectedDomains() });
    const detector = new PhishingDetector({ brands, allowlist: opts.allowlist, protectedBrands: opts.protectedBrands });
    const allow = new Set((opts.allowlist || []).map((x) => x.toLowerCase()));
    return {
      brands, monitor, analyzer, detector,
      addAllowlist(d) { d = normalizeDomain(d); if (!d) return; allow.add(d); analyzer.addAllowlist(d); monitor.addAllowlist(d); detector.allowlist.add(d); },
      removeAllowlist(d) { d = normalizeDomain(d); allow.delete(d); analyzer.removeAllowlist(d); monitor.removeAllowlist(d); detector.allowlist.delete(d); },
      isAllowlisted(d) { return !!matchesAny(normalizeDomain(d), allow); },
      scan(domain, context, source, record) {
        const hostname = normalizeDomain(domain);
        if (!hostname) throw new Error("Domain is required");
        const phishing = detector.analyze(hostname, context);
        const squats = analyzer.analyze(hostname);
        const brandAlerts = monitor.checkDomain(hostname, source || "scan", record !== false);
        const allowlisted = !!matchesAny(hostname, allow);
        if (allowlisted) Object.assign(phishing, { is_phishing: false, risk_level: "clean", risk_score: 0, recommendation: "Domain is allowlisted." });
        return { domain: hostname, input: domain, phishing, domain_squatting: squats, brand_alerts: brandAlerts, allowlisted, analyzed_at: new Date().toISOString() };
      },
    };
  }

  const KCW = {
    version: D.version, data: D,
    punycodeEncode, punycodeDecode, normalizeDomain, toUnicode, parseDomain, splitSuffix, isSubdomainOf, matchesAny,
    scriptOf, scriptsIn, isMixedScript, containsArabic, normalizeArabic, confusableSkeleton, leetNormalize, brandSkeleton,
    shannonEntropy, levenshtein, similarity, typoThreshold, tokensOf, tldRisk, scoreToLevel, bumpLevel,
    detectTechniques, contextSignals, DomainAnalyzer, BrandMonitor, PhishingDetector, createEngine,
  };
  global.KCW = KCW;
  if (typeof module !== "undefined" && module.exports) module.exports = KCW;
})(typeof window !== "undefined" ? window : globalThis);
