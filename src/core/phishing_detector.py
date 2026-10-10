#!/usr/bin/env python3
"""
BrandSentra - Phishing Detection Engine

Multi-layered heuristic scoring for hostnames. Each layer emits weighted
indicators; the capped total becomes a 0-100 risk score:

1. lure keywords (``login``, ``verify``, ``otp`` ...) in attacker-controlled labels,
2. brand impersonation of protected enterprise and global brands (combo-squats, typos,
   leetspeak, IDN homographs, brand labels inside subdomains),
3. public-suffix risk (free / abuse-heavy TLDs),
4. structural anomalies (deep subdomains, hyphen and digit padding,
   embedded ``-com``/``-net`` tokens, fake ``gov``/``ministry`` wording),
5. Shannon entropy of the registrable label,
6. IDN / mixed-script analysis,
7. free-hosting and tunnelling platforms,
8. optional certificate context (free CA + brand match).

Hostnames that belong to a protected brand or the allowlist are returned
as clean with an explaining indicator so operators can see *why*.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from src.core.brand_monitor import DEFAULT_BRANDS
from src.core.constants import (
    ARABIC_PHISHING_KEYWORDS,
    BRAND_TOKENS,
    GLOBAL_BRANDS,
    OFFICIAL_SUFFIXES,
    PHISHING_KEYWORDS,
    score_to_level,
    tld_risk,
)
from src.core.domain_analyzer import context_signals, detect_techniques
from src.utils.domain import (
    ParsedDomain,
    contains_arabic,
    is_mixed_script,
    matches_any,
    normalize_arabic,
    parse_domain,
    scripts_in,
    shannon_entropy,
    tokens_of,
)

logger = logging.getLogger("brandsentra.phishing_detector")

# Backwards compatible exports ------------------------------------------------ #
BRAND_IMPERSONATION_KEYWORDS: List[str] = sorted(BRAND_TOKENS | GLOBAL_BRANDS)
SUSPICIOUS_TLDS = {
    "high_risk": [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".icu"],
    "medium_risk": [".xyz", ".top", ".club", ".online", ".site", ".work", ".click", ".link"],
}

OFFICIAL_TOKENS = {"gov", "govt", "government", "ministry", "e-gov", "egov"}
EMBEDDED_TLD_TOKENS = {"com", "net", "org", "gov", "co"}
FREE_CA_MARKERS = ("let's encrypt", "letsencrypt", "zerossl", "buypass", "google trust services")

CAPS = {
    "keyword_abuse": 36.0,
    "brand_impersonation": 55.0,
    "structural_anomaly": 30.0,
    "idn_attack": 55.0,
}


@dataclass
class PhishingVerdict:
    """Result of phishing analysis."""

    domain: str
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_level: str  # critical, high, medium, low, clean
    indicators: List[Dict[str, Any]]
    categories: List[str]
    recommendation: str
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    parsed: Dict[str, Any] = field(default_factory=dict)
    matched_brands: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "is_phishing": self.is_phishing,
            "confidence": round(self.confidence, 3),
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "indicators": self.indicators,
            "categories": list(self.categories),
            "recommendation": self.recommendation,
            "analyzed_at": self.analyzed_at,
            "parsed": self.parsed,
            "matched_brands": list(self.matched_brands),
            "explanation": self.explanation,
        }


def _indicator(kind: str, detail: str, weight: float, **extra: Any) -> Dict[str, Any]:
    ind: Dict[str, Any] = {"type": kind, "detail": detail, "weight": round(weight, 1)}
    ind.update(extra)
    return ind


class PhishingDetector:
    """Multi-layered phishing detection engine."""

    def __init__(
        self,
        config: Any = None,
        allowlist: Optional[Iterable[str]] = None,
        brands: Optional[List[Any]] = None,
    ):
        self.config = config
        self.detection_count = 0
        self.false_positive_domains: Set[str] = set()

        domain_cfg = getattr(config, "domain_analysis", None)
        self.allowlist: Set[str] = {a.lower() for a in (allowlist or [])}
        self.allowlist.update(a.lower() for a in (getattr(domain_cfg, "allowlist", None) or []))

        self.brands = list(brands) if brands is not None else list(DEFAULT_BRANDS)
        self.protected_domains: List[str] = []
        for b in self.brands:
            for d in getattr(b, "domains", []) or []:
                if d not in self.protected_domains:
                    self.protected_domains.append(d.lower())
        for d in getattr(domain_cfg, "protected_brands", None) or []:
            if d.lower() not in self.protected_domains:
                self.protected_domains.append(d.lower())

        # brand token -> display name
        self.brand_tokens: Dict[str, str] = {}
        for b in self.brands:
            name = getattr(b, "short_name", "") or getattr(b, "name", "")
            for label in getattr(b, "primary_labels", lambda: set())():
                self.brand_tokens.setdefault(label, name)
            for label in getattr(b, "alias_labels", lambda: set())():
                self.brand_tokens.setdefault(label, name)
        for d in self.protected_domains:
            label = parse_domain(d).label
            if len(label) >= 3:
                self.brand_tokens.setdefault(label, label.upper())
        for tok in BRAND_TOKENS:
            self.brand_tokens.setdefault(tok, tok.upper())
        for tok in GLOBAL_BRANDS:
            self.brand_tokens.setdefault(tok, tok.capitalize())
        self._primary_tokens: Set[str] = set()
        for b in self.brands:
            self._primary_tokens |= getattr(b, "primary_labels", lambda: set())()
        self._primary_tokens |= {t for t in GLOBAL_BRANDS if len(t) >= 5}
        self._known_tokens: Set[str] = set(self.brand_tokens)
        self._primary_brand_tokens: Set[str] = set()
        self.brand_priority: Dict[str, str] = {}
        for b in self.brands:
            prio = getattr(b, "priority", "medium")
            for label in getattr(b, "primary_labels", lambda: set())():
                self._primary_brand_tokens.add(label)
                self.brand_priority.setdefault(label, prio)
            for label in getattr(b, "alias_labels", lambda: set())():
                self.brand_priority.setdefault(label, prio)
        for d in getattr(domain_cfg, "protected_brands", None) or []:
            label = parse_domain(d).label
            if len(label) >= 3:
                self._primary_brand_tokens.add(label)
                self.brand_priority.setdefault(label, "high")
        self._monitored_primary = self._primary_brand_tokens

        self.arabic_brand_keywords: Dict[str, str] = {}
        self.arabic_brand_priority: Dict[str, str] = {}
        for b in self.brands:
            name = getattr(b, "short_name", "") or getattr(b, "name", "")
            for kw in getattr(b, "arabic_keywords", []) or []:
                self.arabic_brand_keywords[normalize_arabic(kw)] = name
                self.arabic_brand_priority[name] = getattr(b, "priority", "medium")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def mark_false_positive(self, domain: str) -> None:
        """Treat ``domain`` (and its subdomains) as clean from now on."""
        self.false_positive_domains.add(parse_domain(domain).hostname)

    def analyze_many(self, domains: Iterable[str]) -> List[PhishingVerdict]:
        return [self.analyze(d) for d in domains]

    def analyze(self, domain: str, additional_context: Optional[Dict] = None) -> PhishingVerdict:
        """Run comprehensive phishing analysis on a hostname or URL."""
        self.detection_count += 1
        parsed = parse_domain(domain)
        context = additional_context or {}

        if not parsed.hostname:
            return self._verdict(domain, parsed, [], set(), [], "Empty or invalid input.")

        # Known-good short circuits
        if parsed.hostname in self.false_positive_domains or matches_any(
            parsed.hostname, self.false_positive_domains
        ):
            ind = [_indicator("false_positive_override", "Marked as false positive", 0)]
            return self._verdict(domain, parsed, ind, set(), [], "Marked as false positive.")
        allow_hit = matches_any(parsed.hostname, self.allowlist)
        if allow_hit:
            ind = [_indicator("allowlisted", f"Allowlisted via {allow_hit}", 0)]
            return self._verdict(domain, parsed, ind, set(), [], "Domain is allowlisted.")
        brand_hit = matches_any(parsed.hostname, self.protected_domains)
        if brand_hit:
            ind = [_indicator("protected_brand_domain", f"Official domain of {brand_hit}", 0)]
            return self._verdict(
                domain, parsed, ind, set(), [], "Legitimate protected-brand infrastructure."
            )

        indicators: List[Dict[str, Any]] = []
        categories: Set[str] = set()
        matched_brands: List[str] = []
        total = 0.0

        def add(score: float, cat: Optional[str], inds: List[Dict[str, Any]]) -> None:
            nonlocal total
            if not inds:
                return
            total += score
            indicators.extend(inds)
            if cat:
                categories.add(cat)

        if parsed.is_ip:
            add(
                25.0,
                "structural_anomaly",
                [_indicator("ip_address_host", "Raw IP address used as host", 25)],
            )
            add(*self._check_keywords(parsed))
            return self._finish(
                domain, parsed, indicators, categories, matched_brands, total, context
            )

        if not parsed.valid:
            add(
                8.0,
                "structural_anomaly",
                [_indicator("invalid_hostname", "Hostname contains invalid characters", 8)],
            )

        add(*self._check_keywords(parsed))
        brand_score, brand_inds, brand_cats, matched_brands = self._check_brands(parsed)
        if brand_inds:
            total += brand_score
            indicators.extend(brand_inds)
            categories.update(brand_cats)
        add(*self._check_tld(parsed, bool(brand_inds)))
        add(*self._check_structure(parsed))
        add(*self._check_entropy(parsed))
        idn_score, idn_inds, idn_cats, idn_brands = self._check_idn(parsed)
        if idn_inds:
            total += idn_score
            indicators.extend(idn_inds)
            categories.update(idn_cats)
            matched_brands.extend(b for b in idn_brands if b not in matched_brands)
        add(*self._check_hosting(parsed, bool(brand_inds)))
        add(*self._check_context(parsed, context, bool(brand_inds)))
        if brand_inds and any(i["type"] == "phishing_keyword" for i in indicators):
            add(
                10.0,
                "brand_impersonation",
                [
                    _indicator(
                        "brand_lure_synergy", "Brand look-alike combined with lure keywords", 10
                    )
                ],
            )

        return self._finish(domain, parsed, indicators, categories, matched_brands, total, context)

    # ------------------------------------------------------------------ #
    # Layers
    # ------------------------------------------------------------------ #

    def _check_keywords(self, parsed: ParsedDomain) -> Tuple[float, str, List[Dict[str, Any]]]:
        inds: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        score = 0.0
        labels = parsed.searchable_labels or parsed.labels
        for idx, label in enumerate(labels):
            in_registrable = idx == len(labels) - 1
            found: Set[str] = set()
            for tok in tokens_of(label):
                if tok in PHISHING_KEYWORDS:
                    found.add(tok)
            for kw in PHISHING_KEYWORDS:
                if len(kw) >= 5 and kw in label:
                    found.add(kw)
            for kw in sorted(found):
                if kw in seen:
                    continue
                seen.add(kw)
                weight = 12.0 if in_registrable else 8.0
                score += weight
                where = "registrable label" if in_registrable else "subdomain"
                inds.append(
                    _indicator(
                        "phishing_keyword", f"Lure keyword '{kw}' in {where}", weight, keyword=kw
                    )
                )
        return min(score, CAPS["keyword_abuse"]), "keyword_abuse", inds

    def _check_brands(
        self, parsed: ParsedDomain
    ) -> Tuple[float, List[Dict[str, Any]], Set[str], List[str]]:
        best: Dict[str, Tuple[float, Dict[str, Any], Set[str]]] = {}
        labels = parsed.searchable_labels
        if not labels:
            return 0.0, [], set(), []
        signals_cache: Dict[str, Set[str]] = {}

        for idx, label in enumerate(labels):
            in_registrable = idx == len(labels) - 1
            unicode_label = parsed.unicode_labels[idx] if idx < len(parsed.unicode_labels) else None
            for token, brand_name in self.brand_tokens.items():
                if len(token) < 3:
                    continue
                weight = 0.0
                kind = ""
                cats: Set[str] = set()
                detail = ""
                if label == token:
                    if in_registrable:
                        if token not in self._monitored_primary:
                            continue  # a global brand's own registrable domain
                        weight, kind = 25.0, "brand_tld_swap"
                        detail = f"Brand label '{token}' ({brand_name}) under another suffix"
                        cats.add("brand_impersonation")
                    else:
                        weight, kind = 25.0, "brand_in_subdomain"
                        detail = f"Brand label '{token}' ({brand_name}) used as a subdomain"
                        cats.update({"brand_impersonation", "subdomain_abuse"})
                else:
                    info = detect_techniques(
                        label,
                        token,
                        unicode_label,
                        allow_typo=token in self._primary_tokens,
                        exclude_tokens=self._known_tokens - {token},
                    )
                    techniques = info["techniques"]
                    if not techniques:
                        continue
                    if info["weak"]:
                        if token not in signals_cache:
                            signals_cache[token] = context_signals(parsed, token)
                        if not signals_cache[token]:
                            continue
                    if "homoglyph" in techniques:
                        weight, kind = 40.0, "idn_homograph"
                        cats.update({"brand_impersonation", "idn_attack"})
                        detail = (
                            f"Homograph of '{token}' ({brand_name}): '{unicode_label or label}'"
                        )
                    elif "leet_substitution" in techniques:
                        weight, kind = 45.0, "leet_brand"
                        cats.add("brand_impersonation")
                        detail = f"Leetspeak disguise of '{token}' ({brand_name})"
                    elif "combo_squat" in techniques:
                        weight, kind = (35.0 if in_registrable else 22.0), "brand_combo"
                        cats.add("brand_impersonation")
                        if not in_registrable:
                            cats.add("subdomain_abuse")
                        detail = (
                            f"Brand '{token}' ({brand_name}) combined with "
                            f"{', '.join(info['combo_keywords'][:3])}"
                        )
                    elif "hyphenation" in techniques:
                        weight, kind = 30.0, "brand_hyphenation"
                        cats.add("brand_impersonation")
                        detail = f"Hyphenated brand label '{token}' ({brand_name})"
                    elif "typosquat" in techniques:
                        weight, kind = (15.0 if info["weak"] else 35.0), "brand_typosquat"
                        cats.add("brand_impersonation")
                        detail = f"Typo of '{token}' ({brand_name}): '{label}'"
                    elif "addition" in techniques or "brand_embedding" in techniques:
                        weight, kind = 10.0, "brand_keyword"
                        cats.add("brand_impersonation")
                        detail = f"Brand keyword '{token}' ({brand_name}) embedded in '{label}'"
                    else:
                        continue
                if weight <= 0:
                    continue
                current = best.get(brand_name)
                if current is None or weight > current[0]:
                    best[brand_name] = (
                        weight,
                        _indicator(
                            kind, detail, weight, brand=brand_name, label=label, token=token
                        ),
                        cats,
                    )

        if not best:
            return 0.0, [], set(), []
        ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)
        top_name, (top_weight, top_ind, top_cats) = ranked[0]
        score = top_weight
        inds = [top_ind]
        cats = set(top_cats)
        brands = [top_name]
        priority = self.brand_priority.get(top_ind.get("token", ""), "medium")
        bonus = {"critical": 10.0, "high": 5.0}.get(priority, 0.0)
        if bonus:
            score += bonus
            inds.append(
                _indicator(
                    "brand_priority",
                    f"{top_name} is a {priority}-priority protected brand",
                    bonus,
                    brand=top_name,
                )
            )
        for name, (w, ind, c) in ranked[1:3]:
            score += min(w, 8.0)
            inds.append(ind)
            cats |= c
            brands.append(name)
        return min(score, CAPS["brand_impersonation"]), inds, cats, brands

    @staticmethod
    def _check_tld(
        parsed: ParsedDomain, brand_match: bool
    ) -> Tuple[float, str, List[Dict[str, Any]]]:
        if parsed.hosting_platform:
            # the platform is scored once by _check_hosting; its TLD says nothing about the tenant
            return 0.0, "suspicious_tld", []
        risk = tld_risk(parsed.suffix)
        if risk == "none":
            return 0.0, "suspicious_tld", []
        weight = 20.0 if risk == "high" else 10.0
        inds = [
            _indicator(f"{risk}_risk_tld", f"{risk.capitalize()}-risk TLD: .{parsed.tld}", weight)
        ]
        if brand_match:
            inds.append(
                _indicator("brand_on_risky_tld", "Brand impersonation on an abuse-prone TLD", 8)
            )
            weight += 8.0
        return weight, "suspicious_tld", inds

    @staticmethod
    def _check_structure(parsed: ParsedDomain) -> Tuple[float, str, List[Dict[str, Any]]]:
        inds: List[Dict[str, Any]] = []
        score = 0.0
        label = parsed.unicode_label if parsed.is_idn else parsed.label
        depth = parsed.depth
        if parsed.hostname.split(".")[0] == "www":
            depth -= 1  # a leading www is a convention, not a sign of structure
        if depth >= 4:
            w = 12.0 + (6.0 if depth >= 6 else 0.0)
            score += w
            inds.append(_indicator("excessive_subdomains", f"Hostname has {depth} labels", w))
        hyphens = label.count("-")
        if hyphens >= 3:
            score += 10.0
            inds.append(_indicator("excessive_hyphens", f"Label contains {hyphens} hyphens", 10))
        if len(label) > 25:
            score += 8.0
            inds.append(_indicator("long_domain", f"Unusually long label ({len(label)} chars)", 8))
        digits = sum(c.isdigit() for c in label)
        if digits >= 5:
            score += 8.0
            inds.append(_indicator("numeric_padding", f"Label contains {digits} digits", 8))
        tokens = set()
        for lbl in parsed.searchable_labels:
            tokens.update(tokens_of(lbl))
        embedded = tokens & EMBEDDED_TLD_TOKENS
        if embedded and len(parsed.searchable_labels) >= 1 and (hyphens or parsed.subdomain):
            score += 10.0
            inds.append(
                _indicator(
                    "embedded_tld_token",
                    f"TLD-like token(s) inside labels: {', '.join(sorted(embedded))}",
                    10,
                )
            )
        official = tokens & OFFICIAL_TOKENS
        if (
            official
            and parsed.suffix not in OFFICIAL_SUFFIXES
            and not parsed.suffix.startswith("gov.")
        ):
            score += 12.0
            inds.append(
                _indicator(
                    "fake_official",
                    f"Government wording ({', '.join(sorted(official))}) outside official registry domains",
                    12,
                )
            )
        return min(score, CAPS["structural_anomaly"]), "structural_anomaly", inds

    @staticmethod
    def _check_entropy(parsed: ParsedDomain) -> Tuple[float, str, List[Dict[str, Any]]]:
        label = parsed.label.replace("-", "")
        if len(label) < 10:
            return 0.0, "high_entropy", []
        entropy = shannon_entropy(label)
        threshold = 3.8 if len(label) >= 12 else 4.0
        if entropy >= threshold:
            return (
                12.0,
                "high_entropy",
                [_indicator("high_entropy", f"High entropy label: {entropy:.2f} bits", 12)],
            )
        return 0.0, "high_entropy", []

    def _check_idn(
        self, parsed: ParsedDomain
    ) -> Tuple[float, List[Dict[str, Any]], Set[str], List[str]]:
        if not parsed.is_idn:
            return 0.0, [], set(), []
        inds = [_indicator("punycode_idn", "Internationalized Domain Name (punycode) detected", 12)]
        score = 12.0
        cats = {"idn_attack"}
        brands: List[str] = []
        unicode_label = parsed.unicode_label
        if is_mixed_script(unicode_label):
            scripts = ", ".join(sorted(scripts_in(unicode_label)))
            score += 18.0
            inds.append(_indicator("mixed_script", f"Label mixes scripts: {scripts}", 18))
        if contains_arabic(parsed.unicode_hostname):
            normalized = normalize_arabic(parsed.unicode_hostname)
            lures = [(ar, en) for ar, en in ARABIC_PHISHING_KEYWORDS.items() if ar in normalized][
                :3
            ]
            for ar, en in lures:
                score += 10.0
                inds.append(
                    _indicator("arabic_lure_keyword", f"Arabic lure word '{ar}' ({en})", 10)
                )
            if lures:
                cats.add("keyword_abuse")
            for ar_brand, name in self.arabic_brand_keywords.items():
                if ar_brand and ar_brand in normalized:
                    priority = self.arabic_brand_priority.get(name, "medium")
                    weight = 25.0 + {"critical": 10.0, "high": 5.0}.get(priority, 0.0)
                    score += weight
                    cats.add("brand_impersonation")
                    brands.append(name)
                    inds.append(
                        _indicator(
                            "arabic_brand_keyword",
                            f"Arabic brand keyword for {name}",
                            weight,
                            brand=name,
                        )
                    )
                    break
        return min(score, CAPS["idn_attack"]), inds, cats, brands

    @staticmethod
    def _check_hosting(
        parsed: ParsedDomain, brand_match: bool
    ) -> Tuple[float, str, List[Dict[str, Any]]]:
        if not parsed.hosting_platform:
            return 0.0, "hosting_abuse", []
        weight = 15.0 + (5.0 if brand_match else 0.0)
        return (
            weight,
            "hosting_abuse",
            [
                _indicator(
                    "free_hosting_platform",
                    f"Hosted on shared platform {parsed.hosting_platform}",
                    weight,
                )
            ],
        )

    @staticmethod
    def _check_context(
        parsed: ParsedDomain, context: Dict[str, Any], brand_match: bool
    ) -> Tuple[float, str, List[Dict[str, Any]]]:
        inds: List[Dict[str, Any]] = []
        score = 0.0
        issuer = str(context.get("issuer") or "").lower()
        if issuer and brand_match and any(marker in issuer for marker in FREE_CA_MARKERS):
            score += 5.0
            inds.append(
                _indicator("free_certificate", "Free CA certificate on a brand look-alike", 5)
            )
        if context.get("is_wildcard") or parsed.is_wildcard:
            if brand_match:
                score += 4.0
                inds.append(
                    _indicator(
                        "wildcard_certificate", "Wildcard certificate for a brand look-alike", 4
                    )
                )
        return score, "certificate_context", inds

    # ------------------------------------------------------------------ #
    # Verdict assembly
    # ------------------------------------------------------------------ #

    def _finish(
        self,
        domain: str,
        parsed: ParsedDomain,
        indicators: List[Dict[str, Any]],
        categories: Set[str],
        matched_brands: List[str],
        total: float,
        context: Dict[str, Any],
    ) -> PhishingVerdict:
        risk_score = round(min(total, 100.0), 1)
        level = score_to_level(risk_score)
        summary = self._explain(parsed, indicators, matched_brands, level)
        recommendation = self._generate_recommendation(level, categories, matched_brands)
        return PhishingVerdict(
            domain=domain,
            is_phishing=risk_score >= 50.0,
            confidence=min(risk_score / 100.0, 0.99),
            risk_score=risk_score,
            risk_level=level,
            indicators=indicators,
            categories=sorted(categories),
            recommendation=recommendation,
            parsed=parsed.to_dict(),
            matched_brands=matched_brands,
            explanation=summary,
        )

    def _verdict(
        self,
        domain: str,
        parsed: ParsedDomain,
        indicators: List[Dict[str, Any]],
        categories: Set[str],
        brands: List[str],
        explanation: str,
    ) -> PhishingVerdict:
        return PhishingVerdict(
            domain=domain,
            is_phishing=False,
            confidence=0.0,
            risk_score=0.0,
            risk_level="clean",
            indicators=indicators,
            categories=sorted(categories),
            recommendation=self._generate_recommendation("clean", categories, brands),
            parsed=parsed.to_dict(),
            matched_brands=brands,
            explanation=explanation,
        )

    @staticmethod
    def _explain(
        parsed: ParsedDomain, indicators: List[Dict[str, Any]], brands: List[str], level: str
    ) -> str:
        if not indicators:
            return f"No phishing indicators found for {parsed.hostname}."
        top = sorted(indicators, key=lambda i: i.get("weight", 0), reverse=True)[:3]
        parts = [i["detail"] for i in top]
        prefix = f"{level.upper()} risk"
        if brands:
            prefix += f" (targets {', '.join(brands[:2])})"
        return f"{prefix}: " + "; ".join(parts) + "."

    @staticmethod
    def _score_to_level(score: float) -> str:
        return score_to_level(score)

    @staticmethod
    def _generate_recommendation(
        level: str, categories: Iterable[str], brands: Optional[List[str]] = None
    ) -> str:
        brand_note = f" Notify {brands[0]} security team." if brands else ""
        recs = {
            "critical": "IMMEDIATE ACTION: Block domain, issue takedown request, notify SOC team."
            + brand_note,
            "high": "HIGH PRIORITY: Add to blocklist, investigate registration details, monitor for "
            "active phishing." + brand_note,
            "medium": "MONITOR: Add to watchlist, verify with threat intelligence feeds.",
            "low": "LOW RISK: Log for reference, no immediate action required.",
            "clean": "No threats detected. Domain appears legitimate.",
        }
        return recs.get(level, "Review manually.")


__all__ = [
    "BRAND_IMPERSONATION_KEYWORDS",
    "PHISHING_KEYWORDS",
    "PhishingDetector",
    "PhishingVerdict",
    "SUSPICIOUS_TLDS",
]
