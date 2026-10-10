#!/usr/bin/env python3
"""
BrandSentra - Domain Squatting Analyzer

Detects typosquatting, homoglyph (IDN) attacks, combo-squatting,
bitsquatting, leetspeak substitution, hyphenation, TLD swaps and
subdomain abuse against a list of protected brand domains, and generates
squatting permutations for proactive monitoring.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from src.core.constants import COMBO_KEYWORDS, CONTEXT_TOKENS, tld_risk
from src.utils.domain import (
    CONFUSABLES,
    ParsedDomain,
    brand_skeleton,
    confusable_skeleton,
    leet_normalize,
    levenshtein,
    matches_any,
    parse_domain,
    similarity,
    tokens_of,
    typo_threshold,
)

logger = logging.getLogger("brandsentra.domain_analyzer")

#: Latin look-alikes used when *generating* permutations (display friendly).
HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["à", "á", "â", "ä", "α", "а", "ạ"],
    "b": ["d", "ḅ", "ʙ", "Ь"],
    "c": ["ç", "ć", "с", "ϲ"],
    "d": ["b", "ḍ", "ɗ", "ԁ"],
    "e": ["è", "é", "ê", "ë", "е", "ẹ"],
    "g": ["q", "ɡ", "ġ"],
    "h": ["ḥ", "ħ", "һ"],
    "i": ["1", "l", "í", "ì", "ï", "і", "ı"],
    "k": ["ḳ", "ĸ", "к"],
    "l": ["1", "i", "ł", "ӏ"],
    "m": ["rn", "ṃ", "м"],
    "n": ["ñ", "ṇ", "п"],
    "o": ["0", "ó", "ò", "ö", "ø", "о", "ο"],
    "p": ["ṗ", "р", "ρ"],
    "q": ["g", "ԛ"],
    "r": ["ṛ", "ŗ", "г"],
    "s": ["5", "ṣ", "ś", "ş", "ѕ"],
    "t": ["ṭ", "ţ", "т"],
    "u": ["ú", "ù", "ü", "ū", "ц", "υ"],
    "v": ["ṿ", "ν", "ѵ"],
    "w": ["vv", "ẁ", "ẃ", "ԝ"],
    "x": ["ẋ", "х", "χ"],
    "y": ["ý", "ÿ", "ŷ", "у"],
    "z": ["ẓ", "ź", "ż", "з"],
}

#: QWERTY adjacency for keyboard typos.
KEYBOARD_ADJACENT: Dict[str, str] = {
    "q": "wa",
    "w": "qeas",
    "e": "wrds",
    "r": "etdf",
    "t": "ryfg",
    "y": "tugh",
    "u": "yijh",
    "i": "uojk",
    "o": "iplk",
    "p": "ol",
    "a": "qwsz",
    "s": "weadxz",
    "d": "ersfxc",
    "f": "rtdgcv",
    "g": "tyfhvb",
    "h": "yugjbn",
    "j": "uihknm",
    "k": "oijlm",
    "l": "pk",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
    "1": "2q",
    "2": "13qw",
    "3": "24we",
    "4": "35er",
    "5": "46rt",
    "6": "57ty",
    "7": "68yu",
    "8": "79ui",
    "9": "80io",
    "0": "9op",
}

LEET_GENERATION: Dict[str, List[str]] = {
    "o": ["0"],
    "l": ["1"],
    "i": ["1"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5"],
    "t": ["7"],
    "b": ["8"],
    "g": ["9"],
}

#: Combo keywords worth generating permutations for (most used by kits).
GENERATION_COMBOS: List[str] = [
    "login",
    "secure",
    "verify",
    "online",
    "account",
    "update",
    "support",
    "portal",
    "bank",
    "pay",
    "app",
    "mobile",
    "cloud",
    "corp",
    "global",
    "otp",
    "card",
    "service",
    "help",
    "official",
]

VOWELS = "aeiou"

#: Single-edit techniques that are too collision-prone on short brand names
#: to stand alone; they need contextual corroboration (see ``context_signals``).
WEAK_SHORT_TECHNIQUES = {
    "replacement",
    "keyboard_typo",
    "omission",
    "insertion",
    "vowel_swap",
    "bitsquat",
}

TECHNIQUE_ORDER: List[str] = [
    "tld_swap",
    "homoglyph",
    "leet_substitution",
    "hyphenation",
    "combo_squat",
    "brand_embedding",
    "subdomain_abuse",
    "bitsquat",
    "transposition",
    "omission",
    "repetition",
    "insertion",
    "replacement",
    "keyboard_typo",
    "vowel_swap",
    "addition",
    "typosquat",
]


@dataclass
class DomainAnalysisResult:
    """Result of domain squatting analysis against one protected brand."""

    target_domain: str
    suspicious_domain: str
    attack_types: List[str]
    similarity_score: float
    risk_level: str  # critical, high, medium, low
    details: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    whois_data: Optional[Dict] = None
    dns_records: Optional[Dict] = None
    confidence: float = 0.0
    matched_label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_domain,
            "suspicious_domain": self.suspicious_domain,
            "attack_types": list(self.attack_types),
            "similarity": round(self.similarity_score, 4),
            "risk_level": self.risk_level,
            "confidence": round(self.confidence, 3),
            "matched_label": self.matched_label,
            "details": self.details,
            "timestamp": self.timestamp,
        }


# --------------------------------------------------------------------------- #
# Technique detection on a single label
# --------------------------------------------------------------------------- #

_VOCABULARY: Set[str] = set(COMBO_KEYWORDS) | set(CONTEXT_TOKENS)


def _decompose(remainder: str, vocabulary: Set[str] = _VOCABULARY) -> Optional[List[str]]:
    """
    Split ``remainder`` into words from ``vocabulary`` (digit runs allowed).

    Returns the word list or ``None`` when it cannot be fully decomposed.
    """
    remainder = remainder.strip("-_")
    if not remainder:
        return []
    if remainder.isdigit():
        return [remainder]
    n = len(remainder)
    best: List[Optional[List[str]]] = [None] * (n + 1)
    best[0] = []
    for i in range(1, n + 1):
        for j in range(max(0, i - 20), i):
            if best[j] is None:
                continue
            piece = remainder[j:i]
            if piece in ("-", "_"):
                if best[i] is None:
                    best[i] = list(best[j])
                continue
            piece = piece.strip("-_")
            if piece and (piece in vocabulary or piece.isdigit()):
                candidate = list(best[j]) + [piece]
                if best[i] is None or len(candidate) < len(best[i]):
                    best[i] = candidate
    return best[n]


def _classify_single_edit(label: str, brand: str) -> str:
    """Name the kind of one-edit difference between ``label`` and ``brand``."""
    if len(label) == len(brand) - 1:
        return "omission"
    if len(label) == len(brand) + 1:
        for i, ch in enumerate(label):
            if label[:i] + label[i + 1 :] == brand:
                prev_ch = label[i - 1] if i > 0 else ""
                next_ch = label[i + 1] if i + 1 < len(label) else ""
                if ch in (prev_ch, next_ch):
                    return "repetition"
                return "insertion"
        return "insertion"
    if len(label) == len(brand):
        diffs = [(a, b) for a, b in zip(label, brand) if a != b]
        if len(diffs) == 1:
            a, b = diffs[0]
            if a in VOWELS and b in VOWELS:
                return "vowel_swap"
            xor = ord(a) ^ ord(b)
            if xor and bin(xor).count("1") == 1:
                return "bitsquat"
            if a in KEYBOARD_ADJACENT.get(b, ""):
                return "keyboard_typo"
            return "replacement"
    return "replacement"


def _is_transposition(label: str, brand: str) -> bool:
    if len(label) != len(brand):
        return False
    diffs = [i for i, (a, b) in enumerate(zip(label, brand)) if a != b]
    return (
        len(diffs) == 2
        and diffs[1] == diffs[0] + 1
        and label[diffs[0]] == brand[diffs[1]]
        and label[diffs[1]] == brand[diffs[0]]
    )


def _typo_of(text: str, brand: str, threshold: int) -> Optional[Tuple[int, str]]:
    """Return ``(distance, subtype)`` when ``text`` is a typo of ``brand``."""
    if text == brand:
        return None
    if _is_transposition(text, brand):
        return 2, "transposition"
    distance = levenshtein(text, brand, threshold)
    if 0 < distance <= threshold and abs(len(text) - len(brand)) <= 2:
        if distance == 1:
            return distance, _classify_single_edit(text, brand)
        return distance, ("replacement" if len(text) == len(brand) else "insertion")
    return None


def _empty(matched: bool) -> Dict[str, Any]:
    return {
        "techniques": [],
        "similarity": 1.0 if matched else 0.0,
        "distance": 0 if matched else None,
        "weak": False,
        "combo_keywords": [],
    }


def detect_techniques(
    label: str,
    brand_label: str,
    unicode_label: Optional[str] = None,
    max_distance: Optional[int] = None,
    allow_typo: bool = True,
    exclude_tokens: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Compare a single label with a brand label and name the squatting techniques.

    Args:
        label: ASCII/punycode label controlled by the attacker.
        brand_label: registrable label of the protected brand (``nbk``).
        unicode_label: decoded form of ``label`` when it is an IDN.
        max_distance: hard cap for the edit-distance threshold.
        allow_typo: run edit-distance (typo) detection. Disable for aliases
            and multi-word keywords, which collide with ordinary words.
        exclude_tokens: labels that are themselves protected brands; they are
            never reported as typos of ``brand_label``.

    Returns:
        ``{"techniques": [...], "similarity": float, "distance": int|None,
        "weak": bool, "combo_keywords": [...]}`` where ``weak`` flags a
        short-brand typo match that needs contextual corroboration.
    """
    raw = label.lower()
    brand = brand_label.lower()
    display = (unicode_label or raw).lower()
    if not raw or not brand or raw == brand:
        return _empty(raw == brand)

    techniques: List[str] = []
    combo_keywords: List[str] = []
    weak = False
    distance: Optional[int] = None

    folded = confusable_skeleton(display)  # homoglyphs -> latin, hyphens kept
    hyphenated = leet_normalize(folded)  # + leetspeak, hyphens kept
    skeleton = hyphenated.replace("-", "").replace("_", "")
    is_homoglyph = display != folded

    # 1. Whole-label disguises
    if is_homoglyph and folded.replace("-", "") == brand:
        techniques.append("homoglyph")
    elif skeleton == brand and any(c.isdigit() for c in raw):
        techniques.append("leet_substitution")
    elif skeleton == brand and "-" in raw:
        techniques.append("hyphenation")

    excluded = exclude_tokens or set()
    vocabulary = _VOCABULARY | excluded if excluded else _VOCABULARY

    # 2. Brand embedded with other words (combo squatting)
    plain = folded.replace("-", "").replace("_", "")
    if not techniques and (brand in plain or brand in skeleton):
        tokens = tokens_of(folded)
        rest_candidates: List[str] = []
        if brand in folded:
            rest_candidates.append(folded.replace(brand, "", 1))
        elif brand in plain:
            rest_candidates.append(plain.replace(brand, "", 1))
        if brand in hyphenated:
            rest_candidates.append(hyphenated.replace(brand, "", 1))
        elif brand in skeleton:
            rest_candidates.append(skeleton.replace(brand, "", 1))
        decomposed: Optional[List[str]] = None
        for rest in rest_candidates:
            parts: List[str] = []
            ok = True
            for other in (p for p in re.split(r"[-_]+", rest) if p):
                sub = _decompose(other, vocabulary)
                if sub is None:
                    ok = False
                    break
                parts.extend(sub)
            if ok:
                decomposed = parts
                break
        words = [p for p in (decomposed or []) if not p.isdigit()]
        if decomposed is not None and words:
            techniques.append("combo_squat")
            combo_keywords = words
        elif decomposed is not None and decomposed:
            techniques.append("addition")
        elif brand in tokens or len(brand) >= 5:
            techniques.append("brand_embedding")
        if techniques and is_homoglyph:
            techniques.append("homoglyph")

    # 3. Typosquatting (edit distance, scaled to the brand's length)
    if not techniques and allow_typo and len(skeleton) >= 3:
        if skeleton in brand and len(skeleton) < len(brand):
            return _empty(False)  # generic word contained in a longer brand
        threshold = typo_threshold(len(brand))
        if max_distance is not None:
            threshold = min(threshold, max_distance)
        typo = None if skeleton in excluded else _typo_of(skeleton, brand, threshold)
        if typo:
            distance, subtype = typo
            techniques.extend(["typosquat", subtype])
            weak = len(brand) <= 4 and subtype in WEAK_SHORT_TECHNIQUES
        else:
            # token-level typo: "nbkk-login", "burgn-online"
            tokens = [t for t in tokens_of(hyphenated) if len(t) >= 3]
            for tok in tokens:
                if tok == skeleton or tok in excluded:
                    continue
                typo = _typo_of(tok, brand, threshold)
                if not typo:
                    continue
                others = [t for t in tokens if t != tok]
                if others and all(_decompose(o, vocabulary) is not None for o in others):
                    distance, subtype = typo
                    techniques.extend(["typosquat", subtype, "combo_squat"])
                    combo_keywords = [o for o in others if not o.isdigit()]
                    weak = len(brand) <= 4 and subtype in WEAK_SHORT_TECHNIQUES
                    break
        if techniques and is_homoglyph:
            techniques.append("homoglyph")

    return {
        "techniques": techniques,
        "similarity": similarity(skeleton, brand),
        "distance": distance,
        "weak": weak,
        "combo_keywords": combo_keywords,
    }


def context_signals(parsed: ParsedDomain, brand_label: str) -> Set[str]:
    """Tokens in the hostname that corroborate a weak brand match."""
    signals: Set[str] = set()
    for lbl in parsed.searchable_labels:
        for tok in tokens_of(leet_normalize(lbl)):
            if tok != brand_label and tok in _VOCABULARY and len(tok) > 1:
                signals.add(tok)
    risk = tld_risk(parsed.suffix)
    if risk != "none":
        signals.add(f"tld:{risk}")
    if parsed.hosting_platform:
        signals.add("free_hosting")
    return signals


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


class DomainAnalyzer:
    """Analyzes domains for squatting and impersonation techniques."""

    def __init__(self, config: Any, legitimate_domains: Optional[Iterable[str]] = None):
        self.config = config
        self.protected_brands: List[str] = list(getattr(config, "protected_brands", []) or [])
        self.allowlist: List[str] = list(getattr(config, "allowlist", []) or [])
        self.legitimate_domains: List[str] = [d.lower() for d in (legitimate_domains or [])]
        self.max_distance: int = int(getattr(config, "levenshtein_threshold", 3) or 3)
        self.max_permutations: int = int(getattr(config, "max_permutations", 2000) or 2000)
        self._brand_cache: Dict[str, ParsedDomain] = {}

    # -- configuration helpers -------------------------------------------- #

    def add_brand(self, domain: str) -> None:
        if domain and domain not in self.protected_brands:
            self.protected_brands.append(domain)

    def add_allowlist(self, domain: str) -> None:
        if domain and domain not in self.allowlist:
            self.allowlist.append(domain)

    def add_legitimate(self, domains: Iterable[str]) -> None:
        for d in domains:
            d = d.lower()
            if d and d not in self.legitimate_domains:
                self.legitimate_domains.append(d)

    def _parsed_brand(self, brand: str) -> ParsedDomain:
        if brand not in self._brand_cache:
            self._brand_cache[brand] = parse_domain(brand)
        return self._brand_cache[brand]

    def _known_labels(self) -> Set[str]:
        return {self._parsed_brand(b).label for b in self.protected_brands}

    def is_legitimate(self, hostname: str) -> bool:
        """True when ``hostname`` belongs to a protected brand or the allowlist."""
        return bool(
            matches_any(hostname, self.protected_brands)
            or matches_any(hostname, self.legitimate_domains)
            or matches_any(hostname, self.allowlist)
        )

    # -- analysis ----------------------------------------------------------- #

    def analyze(self, domain: str) -> List[DomainAnalysisResult]:
        """Run full analysis of ``domain`` against every protected brand."""
        parsed = parse_domain(domain)
        if not parsed.valid or parsed.is_ip or not parsed.label:
            return []
        if self.is_legitimate(parsed.hostname):
            return []

        known = self._known_labels()
        results: List[DomainAnalysisResult] = []
        for brand in self.protected_brands:
            result = self._analyze_against(parsed, brand, known)
            if result:
                results.append(result)
        results.sort(key=lambda r: (-r.confidence, -r.similarity_score, r.target_domain))
        return results

    def _analyze_against(
        self, parsed: ParsedDomain, brand: str, known_labels: Set[str]
    ) -> Optional[DomainAnalysisResult]:
        brand_parsed = self._parsed_brand(brand)
        brand_label = brand_parsed.label
        if len(brand_label) < 3:
            return None

        attacks: List[str] = []
        details: Dict[str, Any] = {}
        matched_label = parsed.label
        sim = 0.0
        weak = False

        # 1. Registrable label vs brand label
        if parsed.label == brand_label:
            attacks.append("tld_swap")
            details["original_suffix"] = brand_parsed.suffix
            details["swapped_suffix"] = parsed.suffix
            sim = 1.0
        else:
            # A label that *is* another protected brand is never a typo of this one.
            info = detect_techniques(
                parsed.label,
                brand_label,
                parsed.unicode_label,
                self.max_distance,
                exclude_tokens=known_labels - {brand_label},
            )
            if info["techniques"]:
                attacks.extend(info["techniques"])
                sim = info["similarity"]
                weak = info["weak"]
                if info["distance"] is not None:
                    details["levenshtein_distance"] = info["distance"]
                if info["combo_keywords"]:
                    details["combo_keywords"] = info["combo_keywords"]

        # 2. Subdomain labels impersonating the brand (nbk.com.evil.tk)
        for sub in parsed.subdomain_labels:
            if sub == brand_label or brand_skeleton(sub) == brand_label:
                if not attacks:
                    matched_label = sub
                    sim = max(sim, 0.9)
                attacks.append("subdomain_abuse")
                details["abused_subdomain"] = sub
                break
            sub_info = detect_techniques(sub, brand_label, allow_typo=False)
            if "combo_squat" in sub_info["techniques"] or "homoglyph" in sub_info["techniques"]:
                if not attacks:
                    matched_label = sub
                    sim = max(sim, sub_info["similarity"])
                attacks.append("subdomain_abuse")
                details["abused_subdomain"] = sub
                break
        if parsed.subdomain and brand_parsed.hostname in parsed.subdomain:
            details["contains_brand_hostname"] = True

        if not attacks:
            return None

        signals = context_signals(parsed, brand_label)
        if weak and not signals:
            logger.debug("Dropping weak match %s vs %s (no context)", parsed.hostname, brand)
            return None
        if signals:
            details["context"] = sorted(signals)

        attacks = list(dict.fromkeys(attacks))
        risk, confidence = self._score(attacks, sim, signals, weak)
        return DomainAnalysisResult(
            target_domain=brand,
            suspicious_domain=parsed.original.strip() or parsed.hostname,
            attack_types=attacks,
            similarity_score=sim,
            risk_level=risk,
            details=details,
            confidence=confidence,
            matched_label=matched_label,
        )

    @staticmethod
    def _score(attacks: List[str], sim: float, signals: Set[str], weak: bool) -> Tuple[str, float]:
        """Return ``(risk_level, confidence)`` for a set of techniques."""
        strong = {"homoglyph", "leet_substitution", "combo_squat", "tld_swap"}
        if any(a in strong for a in attacks):
            confidence = 0.8
        elif "subdomain_abuse" in attacks:
            confidence = 0.75
        elif "hyphenation" in attacks:
            confidence = 0.7
        elif "typosquat" in attacks:
            confidence = 0.45 if weak else 0.65
        elif "brand_embedding" in attacks or "addition" in attacks:
            confidence = 0.5
        else:
            confidence = 0.35

        confidence += 0.05 * min(len(signals), 3)
        if sim >= 0.85:
            confidence += 0.05
        confidence = min(confidence, 0.99)

        risky_tld = any(s.startswith("tld:") for s in signals)
        hosted = "free_hosting" in signals
        if "homoglyph" in attacks or "leet_substitution" in attacks:
            level = "critical"
        elif "combo_squat" in attacks and (risky_tld or hosted):
            level = "critical"
        elif "combo_squat" in attacks or "subdomain_abuse" in attacks or "tld_swap" in attacks:
            level = "high"
        elif "hyphenation" in attacks:
            level = "high" if risky_tld else "medium"
        elif "typosquat" in attacks and not weak:
            level = "high" if (sim >= 0.8 and signals) or risky_tld else "medium"
        elif "brand_embedding" in attacks or "addition" in attacks or weak:
            level = "medium" if signals else "low"
        else:
            level = "medium"
        return level, round(confidence, 3)

    # -- backwards compatible helpers -------------------------------------- #

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        return levenshtein(s1, s2)

    @staticmethod
    def _check_bitsquat(domain: str, brand: str) -> bool:
        if len(domain) != len(brand):
            return False
        flips = 0
        for d, b in zip(domain, brand):
            xor = ord(d) ^ ord(b)
            if xor:
                if bin(xor).count("1") != 1:
                    return False
                flips += 1
        return flips == 1

    @staticmethod
    def _check_homoglyph(domain: str, brand: str) -> bool:
        return domain != brand and confusable_skeleton(domain) == brand

    @staticmethod
    def _check_vowel_swap(domain: str, brand: str) -> bool:
        if len(domain) != len(brand):
            return False
        swaps = 0
        for d, b in zip(domain, brand):
            if d != b:
                if d in VOWELS and b in VOWELS:
                    swaps += 1
                else:
                    return False
        return swaps > 0

    @staticmethod
    def _similarity_score(s1: str, s2: str) -> float:
        return similarity(s1, s2)

    # -- permutation generation -------------------------------------------- #

    def generate_permutations(self, brand: str) -> List[str]:
        """Return squatting label permutations of ``brand`` (labels only, sorted)."""
        labels = {p["label"] for p in self._permutation_labels(brand)}
        return sorted(labels)

    def _permutation_labels(self, brand: str) -> List[Dict[str, str]]:
        base = parse_domain(brand).label or brand.split(".")[0].lower()
        seen: Set[str] = set()
        out: List[Dict[str, str]] = []

        def add(label: str, technique: str) -> None:
            if not label or label == base or label in seen:
                return
            if label.startswith("-") or label.endswith("-"):
                return
            seen.add(label)
            out.append({"label": label, "technique": technique})

        n = len(base)
        for i in range(n):  # omission
            add(base[:i] + base[i + 1 :], "omission")
        for i in range(n - 1):  # transposition
            chars = list(base)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            add("".join(chars), "transposition")
        for i in range(n):  # repetition
            add(base[: i + 1] + base[i] + base[i + 1 :], "repetition")
        for i, c in enumerate(base):  # keyboard replacement
            for adj in KEYBOARD_ADJACENT.get(c, ""):
                add(base[:i] + adj + base[i + 1 :], "replacement")
        for i in range(n + 1):  # keyboard insertion
            neighbours: Set[str] = set()
            if i > 0:
                neighbours.update(KEYBOARD_ADJACENT.get(base[i - 1], ""))
            if i < n:
                neighbours.update(KEYBOARD_ADJACENT.get(base[i], ""))
            for adj in sorted(neighbours):
                add(base[:i] + adj + base[i:], "insertion")
        for i, c in enumerate(base):  # vowel swap
            if c in VOWELS:
                for v in VOWELS:
                    if v != c:
                        add(base[:i] + v + base[i + 1 :], "vowel_swap")
        for i, c in enumerate(base):  # bitsquat
            for bit in range(7):
                flipped = chr(ord(c) ^ (1 << bit))
                if flipped.isascii() and (
                    flipped.isdigit() or (flipped.isalpha() and flipped.islower())
                ):
                    add(base[:i] + flipped + base[i + 1 :], "bitsquat")
        for i in range(1, n):  # hyphenation
            add(base[:i] + "-" + base[i:], "hyphenation")
        for i, c in enumerate(base):  # leet
            for sub in LEET_GENERATION.get(c, []):
                add(base[:i] + sub + base[i + 1 :], "leet_substitution")
        for i, c in enumerate(base):  # homoglyph
            for glyph in HOMOGLYPHS.get(c, [])[:3]:
                add(base[:i] + glyph + base[i + 1 :], "homoglyph")
        for extra in ("s", "1", "2", "kw", "q8", "online", "bank", "www"):  # addition
            add(base + extra, "addition")
            if extra == "www":
                add("www" + base, "addition")
        for kw in GENERATION_COMBOS:  # combos
            add(f"{base}-{kw}", "combo_squat")
            add(f"{base}{kw}", "combo_squat")
            add(f"{kw}-{base}", "combo_squat")
            add(f"{kw}{base}", "combo_squat")
        return out

    def generate_permutations_detailed(
        self,
        brand: str,
        tlds: Optional[Iterable[str]] = None,
        include_combos: bool = True,
        include_homoglyphs: bool = True,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        """
        Generate full candidate domains with the technique that produced them.

        Args:
            brand: protected brand domain, e.g. ``nbk.com``.
            tlds: suffixes to combine with each label; defaults to the brand's own
                suffix. ``"com.kw"`` style multi-label suffixes are accepted.
            include_combos: include combo-squat / addition permutations.
            include_homoglyphs: include IDN homoglyph permutations (punycode encoded).
            max_results: cap on the number of candidates.

        Returns:
            List of ``{"domain", "label", "technique", "tld"}`` dicts. The brand's
            own label combined with a *different* suffix is reported as
            ``tld_swap``.
        """
        parsed_brand = parse_domain(brand)
        base = parsed_brand.label or brand.split(".")[0].lower()
        own_suffix = parsed_brand.suffix or "com"
        suffixes = [s.strip(".").lower() for s in (tlds or [own_suffix]) if s and s.strip(".")]
        if not suffixes:
            suffixes = [own_suffix]
        limit = max_results or self.max_permutations

        labels = self._permutation_labels(brand)
        if not include_combos:
            labels = [p for p in labels if p["technique"] not in ("combo_squat", "addition")]
        if not include_homoglyphs:
            labels = [p for p in labels if p["technique"] != "homoglyph"]

        out: List[Dict[str, str]] = []
        seen: Set[str] = set()
        for suffix in suffixes:
            if suffix != own_suffix:
                domain = f"{base}.{suffix}"
                if domain not in seen:
                    seen.add(domain)
                    out.append(
                        {"domain": domain, "label": base, "technique": "tld_swap", "tld": suffix}
                    )
        for suffix in suffixes:
            for perm in labels:
                label = perm["label"]
                if not label.isascii():
                    try:
                        label = label.encode("idna").decode("ascii")
                    except (UnicodeError, ValueError):
                        continue
                domain = f"{label}.{suffix}"
                if domain in seen or domain == parsed_brand.hostname:
                    continue
                seen.add(domain)
                out.append(
                    {
                        "domain": domain,
                        "label": label,
                        "technique": perm["technique"],
                        "tld": suffix,
                    }
                )
                if len(out) >= limit:
                    return out
        return out


__all__ = [
    "CONFUSABLES",
    "DomainAnalysisResult",
    "DomainAnalyzer",
    "GENERATION_COMBOS",
    "HOMOGLYPHS",
    "KEYBOARD_ADJACENT",
    "TECHNIQUE_ORDER",
    "WEAK_SHORT_TECHNIQUES",
    "context_signals",
    "detect_techniques",
]
