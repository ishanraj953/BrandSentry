#!/usr/bin/env python3
"""
BrandSentra - Brand Protection Monitor

Matches hostnames against protected brand profiles (enterprise brands, fintech, telecoms,
government services, airlines, energy companies and more) and raises
brand-impersonation alerts.

Matching rules, in order of confidence:

* the brand's registrable label used under another suffix (``nbk.xyz``),
* IDN homographs and leetspeak of the label (``nbк.com``, ``nbk0nline.com``),
* combo-squats (``nbk-login.com``, ``knetpay.info``),
* typos scaled to the label length (``nbkk.com``, ``bourgan.com``),
* brand label inside a subdomain (``nbk.com.verify-login.tk``),
* multi-word and Arabic-script keywords (``key-finance-house.com``,
  ``بيتك-تحديث.com``).

Anything on a protected brand's own domains (``login.nbk.com``) or on the
allowlist is never reported, and identical (brand, domain) pairs are
deduplicated for a configurable window so a certificate with twenty SANs
produces one alert, not twenty.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from src.core.constants import PHISHING_KEYWORDS, bump_level, tld_risk
from src.core.domain_analyzer import context_signals, detect_techniques
from src.utils.domain import (
    ParsedDomain,
    brand_skeleton,
    contains_arabic,
    is_subdomain_of,
    matches_any,
    normalize_arabic,
    parse_domain,
    tokens_of,
)

logger = logging.getLogger("brandsentra.brand_monitor")

MIN_LABEL_LEN = 3
MIN_PHRASE_LEN = 8
SEVERITY_SCORE = {"critical": 90.0, "high": 70.0, "medium": 50.0, "low": 30.0}


@dataclass
class BrandProfile:
    """Defines a brand to protect."""

    name: str
    domains: List[str]
    keywords: List[str]
    logos: List[str] = field(default_factory=list)
    social_handles: Dict[str, str] = field(default_factory=dict)
    industry: str = ""
    priority: str = "high"  # critical, high, medium, low
    arabic_keywords: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    short_name: str = ""

    def primary_labels(self) -> Set[str]:
        """Registrable labels of the brand's own domains (typo detection applies)."""
        out: Set[str] = set()
        for d in self.domains:
            label = parse_domain(d).label
            if len(label) >= MIN_LABEL_LEN:
                out.add(label)
        return out

    def alias_labels(self) -> Set[str]:
        """Aliases and single-word keywords (exact / combo matching only)."""
        out: Set[str] = set()
        primary = self.primary_labels()
        for alias in self.aliases:
            skel = brand_skeleton(alias)
            if len(skel) >= MIN_LABEL_LEN and skel not in primary:
                out.add(skel)
        for kw in self.keywords:
            if " " not in kw.strip():
                skel = brand_skeleton(kw)
                if len(skel) >= 4 and skel not in primary:
                    out.add(skel)
        return out

    def labels(self) -> Set[str]:
        """All labels that identify this brand."""
        return self.primary_labels() | self.alias_labels()

    def phrases(self) -> List[List[str]]:
        """Multi-word keywords as token lists (``national bank global``)."""
        out = []
        for kw in self.keywords:
            words = [w for w in kw.lower().split() if w]
            if len(words) >= 2:
                out.append(words)
        return out

    def is_legitimate(self, hostname: str) -> bool:
        """True when ``hostname`` is one of the brand's own domains or beneath it."""
        return any(is_subdomain_of(hostname, d) for d in self.domains)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrandProfile":
        return cls(
            name=str(data.get("name", "")).strip(),
            domains=[str(d).lower() for d in data.get("domains", []) or []],
            keywords=[str(k).lower() for k in data.get("keywords", []) or []],
            logos=list(data.get("logos", []) or []),
            social_handles=dict(data.get("social_handles", {}) or {}),
            industry=str(data.get("industry", "")),
            priority=str(data.get("priority", "high")).lower(),
            arabic_keywords=list(data.get("arabic_keywords", []) or []),
            aliases=[str(a).lower() for a in data.get("aliases", []) or []],
            short_name=str(data.get("short_name", "")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "short_name": self.short_name,
            "domains": list(self.domains),
            "keywords": list(self.keywords),
            "arabic_keywords": list(self.arabic_keywords),
            "aliases": list(self.aliases),
            "industry": self.industry,
            "priority": self.priority,
        }


@dataclass
class BrandAlert:
    """Alert generated when brand impersonation is detected."""

    alert_id: str
    brand_name: str
    alert_type: str  # domain_squat, idn_homograph, combo_squat, typosquat, subdomain_abuse, ...
    severity: str
    description: str
    evidence: Dict[str, Any]
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "open"  # open, investigating, resolved, false_positive
    assignee: Optional[str] = None
    risk_score: float = 0.0
    domain: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "brand": self.brand_name,
            "brand_name": self.brand_name,
            "type": self.alert_type,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
            "status": self.status,
            "assignee": self.assignee,
            "risk_score": self.risk_score,
            "domain": self.domain,
        }


# --------------------------------------------------------------------------- #
# Default BrandSentra brand profiles
# --------------------------------------------------------------------------- #

DEFAULT_BRANDS: List[BrandProfile] = [
    BrandProfile(
        name="NovaPay",
        short_name="NovaPay",
        domains=["novapay.com", "novapay.net"],
        keywords=["novapay", "nova pay", "novapay support"],
        aliases=["n0vapay", "novapya"],
        arabic_keywords=["نوفاباي"],
        industry="payments",
        priority="critical",
    ),
    BrandProfile(
        name="Kestrel Mart",
        short_name="Kestrel",
        domains=["kestrelmart.com"],
        keywords=["kestrelmart", "kestrel mart"],
        aliases=["kestrel"],
        industry="ecommerce",
        priority="high",
    ),
    BrandProfile(
        name="Halcyon Health",
        short_name="Halcyon",
        domains=["halcyonhealth.org"],
        keywords=["halcyonhealth", "halcyon health"],
        aliases=["halcyon"],
        industry="healthcare",
        priority="high",
    ),
    BrandProfile(
        name="National Banking Corporation (NBK)",
        short_name="NBK",
        domains=["nbk.com", "nbkcapital.com"],
        keywords=["nbk", "national banking corporation", "watani"],
        aliases=["nbkonline", "nbkbank"],
        arabic_keywords=["الوطني"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Key Finance House (KFH)",
        short_name="KFH",
        domains=["kfh.com"],
        keywords=["kfh", "key finance house", "key finance", "baitak"],
        aliases=["kfhonline", "kfhbank"],
        arabic_keywords=["بيتك"],
        industry="banking",
        priority="critical",
    ),
    BrandProfile(
        name="Central Banking Authority (CBK)",
        short_name="CBK",
        domains=["cbk.com"],
        keywords=["cbk", "central banking authority"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Commercial Banking Group (Al-Tijari)",
        short_name="Al-Tijari",
        domains=["cbk.com", "cbkonline.com"],
        keywords=["commercial banking group", "tijari", "altijari"],
        arabic_keywords=["التجاري"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Burgan Bank",
        short_name="Burgan",
        domains=["burgan.com"],
        keywords=["burgan", "burgan bank"],
        arabic_keywords=["برقان"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Gulf Bank",
        short_name="Gulf Bank",
        domains=["e-gulfbank.com", "gulfbank.com"],
        keywords=["gulfbank", "gulf bank", "egulfbank"],
        arabic_keywords=["بنك الخليج"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Boubyan Bank",
        short_name="Boubyan",
        domains=["bankboubyan.com", "boubyan.com"],
        keywords=["boubyan", "boubyan bank", "bank boubyan"],
        arabic_keywords=["بوبيان"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Warba Bank",
        short_name="Warba",
        domains=["warbabank.com"],
        keywords=["warba", "warba bank"],
        arabic_keywords=["وربة"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Al Ahli Bank (ABK)",
        short_name="ABK",
        domains=["eahli.com"],
        keywords=["abk", "al ahli bank", "eahli"],
        arabic_keywords=["الأهلي"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Global International Bank (KIB)",
        short_name="KIB",
        domains=["kib.com"],
        keywords=["kib", "global international bank"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="Ahli United Bank",
        short_name="AUB",
        domains=["ahliunited.com"],
        keywords=["ahliunited", "ahli united bank", "ahli united"],
        arabic_keywords=["الأهلي المتحد"],
        industry="banking",
        priority="high",
    ),
    BrandProfile(
        name="KNET Electronic Payments",
        short_name="KNET",
        domains=["kpay.com"],
        keywords=["knet", "kpay", "knet payment"],
        aliases=["knetpay", "knetpayment", "knetonline"],
        industry="payments",
        priority="critical",
    ),
    BrandProfile(
        name="Zain Telecom",
        short_name="Zain",
        domains=["zain.com"],
        keywords=["zain", "zain telecom", "zaincash"],
        arabic_keywords=["زين"],
        industry="telecom",
        priority="high",
    ),
    BrandProfile(
        name="Ooredoo Telecom",
        short_name="Ooredoo",
        domains=["ooredoo.com"],
        keywords=["ooredoo", "ooredoo telecom"],
        arabic_keywords=["أوريدو"],
        industry="telecom",
        priority="high",
    ),
    BrandProfile(
        name="stc Telecom",
        short_name="stc",
        domains=["stc.com"],
        keywords=["stc telecom", "stc"],
        aliases=["stconline"],
        arabic_keywords=["اس تي سي"],
        industry="telecom",
        priority="high",
    ),
    BrandProfile(
        name="Centric eGovernment (Sahel)",
        short_name="eGov",
        domains=["e-gov.org"],
        keywords=["egov", "sahel", "sahel portal"],
        aliases=["sahel", "sahelapp"],
        arabic_keywords=["سهل"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Ministry of Interior (MOI)",
        short_name="MOI",
        domains=["moi-gov.org"],
        keywords=["moi", "ministry of interior"],
        aliases=["moigov"],
        arabic_keywords=["الداخلية"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Civil Identity Authority (PACI)",
        short_name="PACI",
        domains=["paci-gov.org"],
        keywords=["paci", "civil information", "civil id", "hawiyati"],
        aliases=["civilid"],
        arabic_keywords=["الهيئة العامة للمعلومات", "البطاقة المدنية", "هويتي"],
        industry="government",
        priority="critical",
    ),
    BrandProfile(
        name="Ministry of Health (MOH)",
        short_name="MOH",
        domains=["moh-gov.org"],
        keywords=["moh", "ministry of health"],
        arabic_keywords=["الصحة"],
        industry="government",
        priority="high",
    ),
    BrandProfile(
        name="Ministry of Education (MOE)",
        short_name="MOE",
        domains=["moe-edu.org"],
        keywords=["moe", "ministry of education"],
        arabic_keywords=["التربية"],
        industry="government",
        priority="medium",
    ),
    BrandProfile(
        name="Global Sky Airways",
        short_name="Global Airways",
        domains=["globalairways.com"],
        keywords=["globalairways", "global airways"],
        industry="aviation",
        priority="high",
    ),
    BrandProfile(
        name="Jazeera Airways",
        short_name="Jazeera",
        domains=["jazeeraairways.com"],
        keywords=["jazeeraairways", "jazeera airways"],
        arabic_keywords=["طيران الجزيرة"],
        industry="aviation",
        priority="medium",
    ),
    BrandProfile(
        name="National Petroleum Company (KNPC)",
        short_name="KNPC",
        domains=["knpc.com"],
        keywords=["knpc", "national petroleum"],
        industry="energy",
        priority="medium",
    ),
    BrandProfile(
        name="Petroleum Corporation (KPC)",
        short_name="KPC",
        domains=["kpc-corp.com"],
        keywords=["kpc", "petroleum corporation"],
        industry="energy",
        priority="medium",
    ),
    BrandProfile(
        name="Securities Exchange (Boursa)",
        short_name="Boursa",
        domains=["boursa-exchange.com"],
        keywords=["boursa", "securities exchange"],
        industry="finance",
        priority="medium",
    ),
    BrandProfile(
        name="Talabat",
        short_name="Talabat",
        domains=["talabat.com"],
        keywords=["talabat"],
        arabic_keywords=["طلبات"],
        industry="ecommerce",
        priority="medium",
    ),
]


# --------------------------------------------------------------------------- #
# Monitor
# --------------------------------------------------------------------------- #

Candidate = Tuple[int, str, str, Dict[str, Any]]  # (rank, alert_type, severity, evidence)


class BrandMonitor:
    """Monitors brand assets and generates alerts on impersonation attempts."""

    def __init__(
        self,
        brands: Optional[List[BrandProfile]] = None,
        dedupe_window_seconds: int = 86400,
        allowlist: Optional[Iterable[str]] = None,
        now: Callable[[], float] = time.time,
    ):
        self.brands: List[BrandProfile] = (
            list(brands) if brands is not None else list(DEFAULT_BRANDS)
        )
        self.alerts: List[BrandAlert] = []
        self.dedupe_window = int(dedupe_window_seconds)
        self.allowlist: List[str] = [a.lower() for a in (allowlist or [])]
        self._now = now
        self._recent: Dict[Tuple[str, str], float] = {}
        self._alert_counter = 0
        self.stats = {"checked": 0, "matched": 0, "deduplicated": 0, "allowlisted": 0}

    # -- construction helpers ---------------------------------------------- #

    @classmethod
    def from_settings(cls, settings: Any) -> "BrandMonitor":
        """Build a monitor from :class:`Settings`, merging custom brand profiles."""
        custom = [BrandProfile.from_dict(b) for b in getattr(settings, "brands", []) or []]
        custom = [b for b in custom if b.name and b.domains]
        if getattr(settings, "brands_replace_defaults", False):
            brands = custom
        else:
            names = {b.name for b in DEFAULT_BRANDS}
            brands = list(DEFAULT_BRANDS) + [b for b in custom if b.name not in names]
        allowlist = getattr(getattr(settings, "domain_analysis", None), "allowlist", []) or []
        return cls(brands=brands, allowlist=allowlist)

    def add_brand(self, brand: BrandProfile) -> None:
        self.brands = [b for b in self.brands if b.name != brand.name]
        self.brands.append(brand)
        logger.info("Added brand monitor: %s", brand.name)

    def remove_brand(self, name: str) -> bool:
        before = len(self.brands)
        self.brands = [b for b in self.brands if b.name != name]
        return len(self.brands) < before

    def get_brand(self, name: str) -> Optional[BrandProfile]:
        lowered = name.lower()
        for b in self.brands:
            if b.name.lower() == lowered or (b.short_name and b.short_name.lower() == lowered):
                return b
        return None

    def find_brand_by_domain(self, domain: str) -> Optional[BrandProfile]:
        host = parse_domain(domain).hostname
        for b in self.brands:
            if b.is_legitimate(host):
                return b
        return None

    def protected_domains(self) -> List[str]:
        """Every domain owned by a monitored brand."""
        out: List[str] = []
        for b in self.brands:
            for d in b.domains:
                if d not in out:
                    out.append(d)
        return out

    def add_allowlist(self, domain: str) -> None:
        domain = domain.lower().strip()
        if domain and domain not in self.allowlist:
            self.allowlist.append(domain)

    def remove_allowlist(self, domain: str) -> None:
        self.allowlist = [d for d in self.allowlist if d != domain.lower().strip()]

    # -- detection --------------------------------------------------------- #

    def check_domain(
        self, domain: str, source: str = "scan", record: bool = True
    ) -> List[BrandAlert]:
        """
        Check a hostname against all monitored brands.

        Args:
            domain: hostname, URL or wildcard certificate name.
            source: origin tag stored in the evidence (``scan``, ``certstream`` ...).
            record: keep generated alerts in :attr:`alerts` and apply dedupe.

        Returns:
            One alert per matching brand (strongest match wins per brand). When
            one brand matches strongly (homograph, squat, combo) weaker typo or
            keyword matches against *other* brands are dropped as noise.
        """
        self.stats["checked"] += 1
        parsed = parse_domain(domain)
        if not parsed.valid or parsed.is_ip or not parsed.label:
            return []
        if matches_any(parsed.hostname, self.allowlist):
            self.stats["allowlisted"] += 1
            return []
        if any(b.is_legitimate(parsed.hostname) for b in self.brands):
            return []

        known_labels: Set[str] = set()
        for b in self.brands:
            known_labels |= b.primary_labels()

        matches: List[Tuple[BrandProfile, Candidate]] = []
        for brand in self.brands:
            candidate = self._match_brand(parsed, brand, known_labels)
            if candidate:
                matches.append((brand, candidate))
        if not matches:
            return []

        top_rank = max(c[0] for _, c in matches)
        if top_rank >= 85:
            matches = [(b, c) for b, c in matches if c[0] >= 85]

        alerts: List[BrandAlert] = []
        for brand, (_, alert_type, severity, evidence) in matches:
            if record and self._is_duplicate(brand.name, parsed.hostname):
                self.stats["deduplicated"] += 1
                continue
            alert = self._build_alert(parsed, brand, alert_type, severity, evidence, source)
            alerts.append(alert)
            if record:
                self.alerts.append(alert)
        if alerts:
            self.stats["matched"] += 1
        return alerts

    def _is_duplicate(self, brand_name: str, hostname: str) -> bool:
        if self.dedupe_window <= 0:
            return False
        key = (brand_name, hostname)
        now = self._now()
        last = self._recent.get(key)
        if last is not None and now - last < self.dedupe_window:
            return True
        self._recent[key] = now
        if len(self._recent) > 50000:
            cutoff = now - self.dedupe_window
            self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        return False

    def _match_brand(
        self, parsed: ParsedDomain, brand: BrandProfile, known_labels: Set[str]
    ) -> Optional[Candidate]:
        """Return the strongest ``(rank, alert_type, severity, evidence)`` match."""
        candidates: List[Candidate] = []
        risky = tld_risk(parsed.suffix)
        phishing_tokens = self._phishing_tokens(parsed)
        primary = brand.primary_labels()
        # Labels that *are* other protected brands are never typos of this one.
        excluded = known_labels - primary

        # 1. Brand labels (primary labels get typo detection, aliases do not)
        for brand_label in sorted(primary, key=len, reverse=True):
            found = self._match_label(
                parsed, brand, brand_label, risky, phishing_tokens, True, excluded
            )
            if found:
                candidates.append(found)
        for brand_label in sorted(brand.alias_labels(), key=len, reverse=True):
            found = self._match_label(
                parsed, brand, brand_label, risky, phishing_tokens, False, excluded
            )
            if found:
                candidates.append(found)

        # 2. Multi-word phrases (national-banking-corporation.com)
        compact = brand_skeleton(parsed.searchable_text.replace(".", ""))
        tokens: Set[str] = set()
        for lbl in parsed.searchable_labels:
            tokens.update(tokens_of(lbl))
        for words in brand.phrases():
            joined = "".join(words)
            significant = [w for w in words if len(w) > 2]
            phrase_hit = len(joined) >= MIN_PHRASE_LEN and joined in compact
            token_hit = len(significant) >= 2 and all(w in tokens for w in significant)
            if phrase_hit or token_hit:
                sev = self._severity_for(brand, "medium", risky, phishing_tokens)
                candidates.append(
                    (40, "brand_keyword_abuse", sev, {"matched_keyword": " ".join(words)})
                )
                break

        # 3. Arabic-script keywords inside IDN labels
        if parsed.is_idn and brand.arabic_keywords:
            unicode_text = normalize_arabic(parsed.unicode_hostname)
            if contains_arabic(unicode_text):
                for kw in brand.arabic_keywords:
                    if normalize_arabic(kw) in unicode_text:
                        sev = self._severity_for(brand, "high", risky, phishing_tokens)
                        evidence = {
                            "matched_keyword": kw,
                            "unicode_hostname": parsed.unicode_hostname,
                        }
                        candidates.append((70, "arabic_brand_keyword", sev, evidence))
                        break

        if not candidates:
            return None
        candidates.sort(key=lambda c: c[0], reverse=True)
        rank, alert_type, severity, evidence = candidates[0]
        if risky != "none":
            evidence["tld_risk"] = risky
        if phishing_tokens:
            evidence["phishing_keywords"] = sorted(phishing_tokens)
        if parsed.hosting_platform:
            evidence["hosting_platform"] = parsed.hosting_platform
        return rank, alert_type, severity, evidence

    def _match_label(
        self,
        parsed: ParsedDomain,
        brand: BrandProfile,
        brand_label: str,
        risky: str,
        phishing_tokens: Set[str],
        allow_typo: bool,
        excluded: Optional[Set[str]] = None,
    ) -> Optional[Candidate]:
        base = brand.priority if brand.priority in SEVERITY_SCORE else "high"
        sev = self._severity_for

        # Registrable label identical to the brand label under another suffix
        if parsed.label == brand_label:
            evidence = {"technique": "tld_swap", "matched_label": parsed.label}
            return 90, "domain_squat", sev(brand, base, risky, phishing_tokens), evidence

        info = detect_techniques(
            parsed.label,
            brand_label,
            parsed.unicode_label,
            allow_typo=allow_typo,
            exclude_tokens=excluded,
        )
        techniques = list(info["techniques"])
        if techniques and info["weak"] and not context_signals(parsed, brand_label):
            techniques = []
        if techniques:
            evidence: Dict[str, Any] = {
                "technique": techniques[0],
                "techniques": techniques,
                "matched_label": parsed.label,
                "similarity": round(info["similarity"], 3),
            }
            if info["combo_keywords"]:
                evidence["combo_keywords"] = info["combo_keywords"]
            if parsed.is_idn:
                evidence["unicode_label"] = parsed.unicode_label
            if "homoglyph" in techniques:
                return 95, "idn_homograph", "critical", evidence
            if "leet_substitution" in techniques:
                return 88, "domain_squat", sev(brand, base, risky, phishing_tokens, 1), evidence
            if "combo_squat" in techniques:
                return 85, "combo_squat", sev(brand, base, risky, phishing_tokens), evidence
            if "typosquat" in techniques or "hyphenation" in techniques:
                level = "high" if base == "critical" else "medium"
                if info["weak"]:
                    level = "medium"
                kind = "domain_squat" if "hyphenation" in techniques else "typosquat"
                return 80, kind, sev(brand, level, risky, phishing_tokens), evidence
            if "addition" in techniques:
                return 60, "domain_squat", sev(brand, "medium", risky, phishing_tokens), evidence
            if "brand_embedding" in techniques:
                level = "medium" if base in ("critical", "high") else "low"
                return (
                    55,
                    "brand_keyword_abuse",
                    sev(brand, level, risky, phishing_tokens),
                    evidence,
                )

        # Subdomain labels
        for sub in parsed.subdomain_labels:
            if sub == brand_label or brand_skeleton(sub) == brand_label:
                level = "critical" if base == "critical" else "high"
                evidence = {"abused_subdomain": sub, "matched_label": brand_label}
                return 75, "subdomain_abuse", sev(brand, level, risky, phishing_tokens), evidence
            sub_info = detect_techniques(sub, brand_label, allow_typo=False)
            if "combo_squat" in sub_info["techniques"]:
                evidence = {
                    "abused_subdomain": sub,
                    "matched_label": brand_label,
                    "combo_keywords": sub_info["combo_keywords"],
                }
                return 72, "subdomain_abuse", sev(brand, "high", risky, phishing_tokens), evidence
        return None

    @staticmethod
    def _phishing_tokens(parsed: ParsedDomain) -> Set[str]:
        found: Set[str] = set()
        for lbl in parsed.searchable_labels:
            for tok in tokens_of(lbl):
                if tok in PHISHING_KEYWORDS:
                    found.add(tok)
            for kw in PHISHING_KEYWORDS:
                if len(kw) >= 5 and kw in lbl:
                    found.add(kw)
        return found

    @staticmethod
    def _severity_for(
        brand: BrandProfile,
        base: str,
        risky: str,
        phishing_tokens: Set[str],
        extra_steps: int = 0,
    ) -> str:
        level = base if base in SEVERITY_SCORE else "medium"
        steps = extra_steps
        if risky == "high":
            steps += 1
        if phishing_tokens:
            steps += 1
        return bump_level(level, steps) if steps else level

    def _build_alert(
        self,
        parsed: ParsedDomain,
        brand: BrandProfile,
        alert_type: str,
        severity: str,
        evidence: Dict[str, Any],
        source: str,
    ) -> BrandAlert:
        self._alert_counter += 1
        digest = hashlib.sha1(
            f"{brand.name}|{parsed.hostname}|{self._now():.3f}|{self._alert_counter}".encode()
        ).hexdigest()[:10]
        evidence = {
            "suspicious_domain": parsed.hostname,
            "registrable_domain": parsed.registrable,
            "protected_domains": list(brand.domains),
            "brand": brand.name,
            "source": source,
            **evidence,
        }
        descriptions = {
            "domain_squat": f"Domain squatting of {brand.name}: {parsed.hostname}",
            "idn_homograph": (
                f"IDN homograph attack impersonating {brand.name}: "
                f"{parsed.unicode_hostname} ({parsed.hostname})"
            ),
            "combo_squat": f"Combo-squat targeting {brand.name}: {parsed.hostname}",
            "typosquat": f"Typosquat of {brand.name}: {parsed.hostname}",
            "subdomain_abuse": f"{brand.name} label abused in subdomain: {parsed.hostname}",
            "brand_keyword_abuse": (
                f"Brand keyword for {brand.name} found in domain: {parsed.hostname}"
            ),
            "arabic_brand_keyword": (
                f"Arabic brand keyword for {brand.name} in IDN domain: {parsed.unicode_hostname}"
            ),
        }
        return BrandAlert(
            alert_id=f"BA-{digest}",
            brand_name=brand.name,
            alert_type=alert_type,
            severity=severity,
            description=descriptions.get(alert_type, f"Brand impersonation of {brand.name}"),
            evidence=evidence,
            risk_score=SEVERITY_SCORE.get(severity, 50.0),
            domain=parsed.hostname,
        )

    # -- alert management -------------------------------------------------- #

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        brand: Optional[str] = None,
    ) -> List[BrandAlert]:
        results = self.alerts
        if status:
            results = [a for a in results if a.status == status]
        if severity:
            results = [a for a in results if a.severity == severity]
        if brand:
            lowered = brand.lower()
            results = [a for a in results if lowered in a.brand_name.lower()]
        return list(results)

    def update_alert_status(
        self, alert_id: str, status: str, assignee: Optional[str] = None
    ) -> Optional[BrandAlert]:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = status
                if assignee is not None:
                    alert.assignee = assignee
                return alert
        return None

    def clear_alerts(self) -> None:
        self.alerts.clear()
        self._recent.clear()

    def get_stats(self) -> Dict[str, Any]:
        by_brand = self._count_by("brand_name")
        by_industry: Dict[str, int] = {}
        for b in self.brands:
            if b.name in by_brand:
                by_industry[b.industry] = by_industry.get(b.industry, 0) + by_brand[b.name]
        return {
            "total_brands": len(self.brands),
            "total_alerts": len(self.alerts),
            "open_alerts": len([a for a in self.alerts if a.status == "open"]),
            "critical_alerts": len([a for a in self.alerts if a.severity == "critical"]),
            "by_type": self._count_by("alert_type"),
            "by_severity": self._count_by("severity"),
            "by_brand": by_brand,
            "by_industry": by_industry,
            "checked": self.stats["checked"],
            "deduplicated": self.stats["deduplicated"],
            "allowlisted": self.stats["allowlisted"],
        }

    def _count_by(self, attr: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for alert in self.alerts:
            val = getattr(alert, attr)
            counts[val] = counts.get(val, 0) + 1
        return counts


__all__ = ["BrandAlert", "BrandMonitor", "BrandProfile", "DEFAULT_BRANDS", "MIN_LABEL_LEN"]
