#!/usr/bin/env python3
"""
BrandSentra - Domain Parsing & Normalisation Utilities

Every detection engine in the suite needs the same handful of primitives:

* turn whatever the user (or a certificate) hands us into a clean hostname,
* split that hostname into subdomain / registrable label / public suffix,
  with correct handling of second-level and international
  registries (``com.co``, ``gov.uk``, ``com.sa`` ...) and of free-hosting
  platforms that behave like public suffixes (``web.app``, ``github.io`` ...),
* decode punycode so IDN homograph attacks can be inspected in Unicode,
* classify the scripts used in a label and collapse confusable characters
  back to their Latin look-alikes,
* normalise Arabic text so Arabic-script brand keywords can be matched.

The module is dependency free and safe to import anywhere.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Public suffix knowledge
# --------------------------------------------------------------------------- #

#: Multi-level national registries. A hostname such as ``login.company.com.kw``
#: has the registrable label ``company`` and the suffix ``com.kw``.
REGIONAL_SUFFIXES: Set[str] = {
    "com.kw",
    "gov.kw",
    "edu.kw",
    "org.kw",
    "net.kw",
    "mil.kw",
    "emb.kw",
    "ind.kw",
}

#: Second-level registries across the GCC / MENA region.
GCC_MENA_SUFFIXES: Set[str] = {
    # Saudi Arabia
    "com.sa",
    "gov.sa",
    "edu.sa",
    "org.sa",
    "net.sa",
    "med.sa",
    "sch.sa",
    "pub.sa",
    # Qatar
    "com.qa",
    "gov.qa",
    "edu.qa",
    "org.qa",
    "net.qa",
    "mil.qa",
    # Bahrain
    "com.bh",
    "gov.bh",
    "edu.bh",
    "org.bh",
    "net.bh",
    # Oman
    "com.om",
    "gov.om",
    "edu.om",
    "org.om",
    "net.om",
    "med.om",
    # United Arab Emirates
    "co.ae",
    "gov.ae",
    "ac.ae",
    "org.ae",
    "net.ae",
    "sch.ae",
    "mil.ae",
    # Egypt
    "com.eg",
    "gov.eg",
    "edu.eg",
    "org.eg",
    "net.eg",
    "eun.eg",
    # Jordan
    "com.jo",
    "gov.jo",
    "edu.jo",
    "org.jo",
    "net.jo",
    # Lebanon
    "com.lb",
    "gov.lb",
    "edu.lb",
    "org.lb",
    "net.lb",
    # Iraq
    "com.iq",
    "gov.iq",
    "edu.iq",
    "org.iq",
    "net.iq",
    # Turkey
    "com.tr",
    "gov.tr",
    "edu.tr",
    "org.tr",
    "net.tr",
    "bel.tr",
    # Iran / Pakistan / Morocco / Tunisia / Algeria
    "co.ir",
    "ac.ir",
    "gov.ir",
    "org.ir",
    "com.pk",
    "gov.pk",
    "edu.pk",
    "org.pk",
    "net.pk",
    "co.ma",
    "gov.ma",
    "ac.ma",
    "org.ma",
    "com.tn",
    "gov.tn",
    "org.tn",
    "com.dz",
    "gov.dz",
    "edu.dz",
}

#: Common second-level registries elsewhere in the world.
GLOBAL_SUFFIXES: Set[str] = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "me.uk",
    "net.uk",
    "ltd.uk",
    "plc.uk",
    "nhs.uk",
    "sch.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "co.nz",
    "org.nz",
    "net.nz",
    "govt.nz",
    "ac.nz",
    "co.za",
    "org.za",
    "gov.za",
    "ac.za",
    "com.br",
    "gov.br",
    "org.br",
    "net.br",
    "edu.br",
    "co.in",
    "org.in",
    "net.in",
    "gov.in",
    "ac.in",
    "firm.in",
    "co.jp",
    "ne.jp",
    "or.jp",
    "go.jp",
    "ac.jp",
    "com.cn",
    "gov.cn",
    "org.cn",
    "net.cn",
    "edu.cn",
    "com.my",
    "gov.my",
    "edu.my",
    "org.my",
    "net.my",
    "com.sg",
    "gov.sg",
    "edu.sg",
    "org.sg",
    "net.sg",
    "com.hk",
    "gov.hk",
    "org.hk",
    "edu.hk",
    "net.hk",
    "com.tw",
    "gov.tw",
    "org.tw",
    "edu.tw",
    "net.tw",
    "com.mx",
    "gob.mx",
    "org.mx",
    "edu.mx",
    "com.ar",
    "gob.ar",
    "org.ar",
    "edu.ar",
    "com.ph",
    "gov.ph",
    "org.ph",
    "edu.ph",
    "co.kr",
    "or.kr",
    "go.kr",
    "ac.kr",
    "ne.kr",
    "com.ng",
    "gov.ng",
    "org.ng",
    "edu.ng",
    "com.bd",
    "gov.bd",
    "edu.bd",
    "org.bd",
    "co.il",
    "org.il",
    "gov.il",
    "ac.il",
    "net.il",
    "com.ua",
    "gov.ua",
    "org.ua",
    "net.ua",
    "co.id",
    "go.id",
    "or.id",
    "ac.id",
    "web.id",
    "com.vn",
    "gov.vn",
    "org.vn",
    "edu.vn",
    "net.vn",
    "com.pe",
    "gob.pe",
    "com.co",
    "gov.co",
    "edu.co",
    "com.ec",
    "gob.ec",
    "com.ve",
    "gob.ve",
    "com.uy",
    "gub.uy",
    "com.py",
    "gov.py",
    "com.bo",
    "gob.bo",
    "com.do",
    "gob.do",
    "com.gt",
    "gob.gt",
    "com.sv",
    "gob.sv",
    "com.pa",
    "gob.pa",
    "com.pr",
    "gov.pr",
    "com.ru",
    "org.ru",
    "net.ru",
    "com.pl",
    "org.pl",
    "net.pl",
    "gov.pl",
    "edu.pl",
    "co.th",
    "go.th",
    "or.th",
    "ac.th",
    "com.np",
    "gov.np",
    "com.lk",
    "gov.lk",
    "com.kz",
    "gov.kz",
    "com.ke",
    "go.ke",
    "co.ke",
    "or.ke",
    "com.gh",
    "gov.gh",
    "edu.gh",
    "co.tz",
    "go.tz",
    "co.ug",
    "go.ug",
    "com.et",
    "gov.et",
}

#: Hosting / tunnelling / site-builder platforms where each subdomain belongs
#: to a different (often anonymous) tenant. They are treated as public
#: suffixes for label extraction *and* flagged as an indicator, because they
#: are a favourite of phishing kits.
FREE_HOSTING_SUFFIXES: Set[str] = {
    "github.io",
    "gitlab.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "azurewebsites.net",
    "azurestaticapps.net",
    "blob.core.windows.net",
    "cloudfront.net",
    "s3.amazonaws.com",
    "s3-website.amazonaws.com",
    "appspot.com",
    "googleusercontent.com",
    "blogspot.com",
    "wordpress.com",
    "weebly.com",
    "wixsite.com",
    "webflow.io",
    "glitch.me",
    "repl.co",
    "replit.app",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "000webhostapp.com",
    "duckdns.org",
    "no-ip.org",
    "ddns.net",
    "hopto.org",
    "sytes.net",
    "zapto.org",
    "myftp.org",
    "serveo.net",
    "loca.lt",
    "surge.sh",
    "onrender.com",
    "fly.dev",
    "railway.app",
    "carrd.co",
    "godaddysites.com",
    "square.site",
    "mystrikingly.com",
    "yolasite.com",
    "webnode.page",
    "jimdosite.com",
    "sites.google.com",
    "forms.gle",
    "typeform.com",
    "notion.site",
    "linktr.ee",
    "bio.link",
    "t.me",
    "telegra.ph",
    "ipfs.io",
    "ipfs.dweb.link",
    "dweb.link",
    "web.core.windows.net",
    "z13.web.core.windows.net",
    "sharepoint.com",
    "my.sharepoint.com",
    "canva.site",
    "my.canva.site",
    "wixstudio.io",
    "framer.app",
    "framer.website",
    "softr.app",
    "bubbleapps.io",
    "glideapp.io",
    "web-app.com",
    "webador.com",
    "mailchimpsites.com",
}

ALL_MULTI_LABEL_SUFFIXES: Set[str] = (
    REGIONAL_SUFFIXES | GCC_MENA_SUFFIXES | GLOBAL_SUFFIXES | FREE_HOSTING_SUFFIXES
)

_MAX_SUFFIX_LABELS = max(s.count(".") + 1 for s in ALL_MULTI_LABEL_SUFFIXES)

# --------------------------------------------------------------------------- #
# Character knowledge
# --------------------------------------------------------------------------- #

#: Single-character confusables mapped back to the ASCII letter they imitate.
#: Sources: Unicode UTS #39 confusables (curated subset), plus the Cyrillic,
#: Greek and Armenian letters most often abused in IDN homograph attacks.
CONFUSABLES: Dict[str, str] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "с": "c",
    "ԁ": "d",
    "е": "e",
    "ё": "e",
    "є": "e",
    "ғ": "f",
    "ց": "g",
    "һ": "h",
    "н": "h",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "к": "k",
    "ӏ": "l",
    "м": "m",
    "п": "n",
    "о": "o",
    "ө": "o",
    "р": "p",
    "ԛ": "q",
    "г": "r",
    "ѕ": "s",
    "т": "t",
    "ц": "u",
    "ѵ": "v",
    "ԝ": "w",
    "х": "x",
    "у": "y",
    "ү": "y",
    "з": "z",
    "ь": "b",
    "ъ": "b",
    # Greek
    "α": "a",
    "β": "b",
    "ϲ": "c",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "μ": "u",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "γ": "y",
    "ω": "w",
    "ϳ": "j",
    "ϱ": "p",
    "ϖ": "w",
    # Armenian
    "օ": "o",
    "ա": "a",
    "ս": "u",
    "ո": "n",
    "հ": "h",
    "ք": "p",
    "զ": "q",
    "ժ": "d",
    # Latin extended / phonetic
    "ı": "i",
    "ł": "l",
    "ø": "o",
    "đ": "d",
    "ð": "d",
    "þ": "p",
    "ƒ": "f",
    "ɑ": "a",
    "ɡ": "g",
    "ɩ": "i",
    "ɪ": "i",
    "ʀ": "r",
    "ʙ": "b",
    "ɴ": "n",
    "ʏ": "y",
    "ʟ": "l",
    "ᴀ": "a",
    "ᴄ": "c",
    "ᴇ": "e",
    "ᴊ": "j",
    "ᴋ": "k",
    "ᴍ": "m",
    "ᴏ": "o",
    "ᴘ": "p",
    "ᴛ": "t",
    "ᴜ": "u",
    "ᴠ": "v",
    "ᴡ": "w",
    "ᴢ": "z",
    "ꜱ": "s",
    "ɢ": "g",
    "ꞵ": "b",
    "ℓ": "l",
    "ℯ": "e",
    "ℴ": "o",
    "ⅰ": "i",
    "ⅼ": "l",
    "ⅽ": "c",
    "ⅾ": "d",
    "ⅿ": "m",
    "ⅴ": "v",
    "ⅹ": "x",
    "ꝺ": "d",
    "ꬲ": "e",
    "ｅ": "e",
}

#: Digits and symbols commonly used as letter substitutes ("leetspeak") in
#: typosquats such as ``nbk0nline`` or ``g00gle``. Mapping is applied only
#: when comparing against brand names, never for display.
LEET_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "l",
}

#: Multi-character Latin sequences that visually resemble a single letter.
VISUAL_SEQUENCES: Tuple[Tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
)

_ARABIC_DIACRITICS = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭـ]")
_ARABIC_RANGE = re.compile(r"[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]")

_IPV4_RE = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_LABEL_OK_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class ParsedDomain:
    """Structured view of a hostname."""

    original: str
    hostname: str  # normalised ASCII/punycode form, lowercase
    unicode_hostname: str  # punycode decoded (== hostname when not IDN)
    labels: List[str]  # ASCII labels, left to right
    subdomain: str  # everything left of the registrable label
    label: str  # registrable label, e.g. "nbk" for login.nbk.com.kw
    suffix: str  # public suffix, e.g. "com.kw"
    tld: str  # last label only, e.g. "kw"
    registrable: str  # label + suffix, e.g. "nbk.com.kw"
    is_idn: bool = False
    is_wildcard: bool = False
    is_ip: bool = False
    hosting_platform: Optional[str] = None
    unicode_labels: List[str] = field(default_factory=list)
    valid: bool = True

    @property
    def unicode_label(self) -> str:
        """Registrable label in decoded (Unicode) form."""
        if not self.unicode_labels or not self.label or self.is_ip or not self.suffix:
            return self.label
        idx = len(self.labels) - self.suffix.count(".") - 2
        if 0 <= idx < len(self.unicode_labels):
            return self.unicode_labels[idx]
        return self.label

    @property
    def depth(self) -> int:
        """Number of labels in the hostname."""
        return len(self.labels)

    @property
    def subdomain_labels(self) -> List[str]:
        return [x for x in self.subdomain.split(".") if x]

    @property
    def searchable_labels(self) -> List[str]:
        """All labels except the public suffix - the parts an attacker controls."""
        n_suffix = self.suffix.count(".") + 1 if self.suffix else 0
        return self.labels[: len(self.labels) - n_suffix] if n_suffix else list(self.labels)

    @property
    def searchable_text(self) -> str:
        return ".".join(self.searchable_labels)

    def to_dict(self) -> Dict:
        return {
            "hostname": self.hostname,
            "unicode_hostname": self.unicode_hostname,
            "subdomain": self.subdomain,
            "label": self.label,
            "suffix": self.suffix,
            "tld": self.tld,
            "registrable": self.registrable,
            "is_idn": self.is_idn,
            "is_wildcard": self.is_wildcard,
            "is_ip": self.is_ip,
            "hosting_platform": self.hosting_platform,
            "depth": self.depth,
            "valid": self.valid,
        }


# --------------------------------------------------------------------------- #
# Normalisation & parsing
# --------------------------------------------------------------------------- #


def normalize_domain(raw: str) -> str:
    """
    Reduce user / certificate input to a bare lowercase hostname.

    Strips URL schemes, credentials, ports, paths, query strings, fragments,
    surrounding whitespace, trailing dots and a leading wildcard marker.
    Unicode labels are converted to punycode where possible.
    """
    if raw is None:
        return ""
    value = str(raw).strip()
    if not value:
        return ""

    value = _SCHEME_RE.sub("", value)
    # Drop path / query / fragment
    for sep in ("/", "?", "#", "\\"):
        idx = value.find(sep)
        if idx != -1:
            value = value[:idx]
    # Drop userinfo
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    # Drop port (but keep IPv6 literals untouched)
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host
    value = value.strip().strip(".").lower()
    if value.startswith("*."):
        value = value[2:]
    value = value.lstrip(".")

    labels = []
    for label in value.split("."):
        if not label:
            continue
        labels.append(_to_ascii_label(label))
    return ".".join(labels)


def _to_ascii_label(label: str) -> str:
    """Punycode-encode a single label if it contains non-ASCII characters."""
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Fall back to NFKC-normalised text; still non-ASCII but stable.
        return unicodedata.normalize("NFKC", label)


def to_unicode(hostname: str) -> str:
    """Decode every punycode label of ``hostname``; invalid labels are kept as is."""
    out = []
    for label in hostname.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def to_ascii(hostname: str) -> str:
    """Punycode-encode every label of ``hostname``."""
    return ".".join(_to_ascii_label(x) for x in hostname.split(".") if x)


def split_suffix(labels: List[str]) -> Tuple[List[str], str]:
    """
    Split ``labels`` into (non-suffix labels, suffix string).

    The longest known multi-label suffix wins; otherwise the last label.
    """
    if not labels:
        return [], ""
    for n in range(min(_MAX_SUFFIX_LABELS, len(labels) - 1), 1, -1):
        candidate = ".".join(labels[-n:])
        if candidate in ALL_MULTI_LABEL_SUFFIXES:
            return labels[:-n], candidate
    if len(labels) == 1:
        return [], labels[0]
    return labels[:-1], labels[-1]


def parse_domain(raw: str) -> ParsedDomain:
    """Parse any hostname-like input into a :class:`ParsedDomain`."""
    original = "" if raw is None else str(raw)
    stripped = original.strip().lower()
    is_wildcard = stripped.startswith("*.")
    hostname = normalize_domain(original)

    if not hostname:
        return ParsedDomain(
            original=original,
            hostname="",
            unicode_hostname="",
            labels=[],
            subdomain="",
            label="",
            suffix="",
            tld="",
            registrable="",
            is_wildcard=is_wildcard,
            valid=False,
        )

    if _IPV4_RE.match(hostname):
        return ParsedDomain(
            original=original,
            hostname=hostname,
            unicode_hostname=hostname,
            labels=hostname.split("."),
            subdomain="",
            label=hostname,
            suffix="",
            tld="",
            registrable=hostname,
            is_ip=True,
            is_wildcard=is_wildcard,
            unicode_labels=hostname.split("."),
        )

    labels = hostname.split(".")
    unicode_hostname = to_unicode(hostname)
    unicode_labels = unicode_hostname.split(".")
    is_idn = any(lbl.startswith("xn--") for lbl in labels) or not hostname.isascii()

    rest, suffix = split_suffix(labels)
    hosting = suffix if suffix in FREE_HOSTING_SUFFIXES else None

    if rest:
        label = rest[-1]
        subdomain = ".".join(rest[:-1])
        registrable = f"{label}.{suffix}" if suffix else label
    else:
        label = ""
        subdomain = ""
        registrable = suffix

    tld = labels[-1]
    valid = all(_LABEL_OK_RE.match(lbl) for lbl in labels) and len(hostname) <= 253

    return ParsedDomain(
        original=original,
        hostname=hostname,
        unicode_hostname=unicode_hostname,
        labels=labels,
        subdomain=subdomain,
        label=label,
        suffix=suffix,
        tld=tld,
        registrable=registrable,
        is_idn=is_idn,
        is_wildcard=is_wildcard,
        hosting_platform=hosting,
        unicode_labels=unicode_labels,
        valid=valid,
    )


def registrable_domain(raw: str) -> str:
    """Convenience wrapper returning only the registrable domain (eTLD+1)."""
    return parse_domain(raw).registrable


def is_subdomain_of(hostname: str, parent: str) -> bool:
    """True when ``hostname`` equals ``parent`` or sits underneath it."""
    h = normalize_domain(hostname)
    p = normalize_domain(parent)
    if not h or not p:
        return False
    return h == p or h.endswith("." + p)


def matches_any(hostname: str, parents: Iterable[str]) -> Optional[str]:
    """Return the first entry of ``parents`` that ``hostname`` belongs to."""
    for parent in parents:
        if is_subdomain_of(hostname, parent):
            return parent
    return None


# --------------------------------------------------------------------------- #
# Script analysis & confusables
# --------------------------------------------------------------------------- #


def script_of(char: str) -> str:
    """
    Coarse Unicode script name for ``char``.

    Digits, hyphens and punctuation are ``COMMON``. Unknown characters are
    ``UNKNOWN``.
    """
    if not char:
        return "UNKNOWN"
    if char.isdigit() or char in "-_.":
        return "COMMON"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "UNKNOWN"
    first = name.split(" ")[0]
    if first in {"DIGIT", "HYPHEN", "FULL", "LOW", "SPACE"}:
        return "COMMON"
    if first in {"CJK", "HIRAGANA", "KATAKANA", "HANGUL"}:
        return "CJK"
    if name.startswith("ARABIC"):
        return "ARABIC"
    return first


def scripts_in(text: str) -> Set[str]:
    """Set of scripts used by ``text`` (``COMMON`` excluded)."""
    return {script_of(c) for c in text} - {"COMMON"}


def is_mixed_script(text: str) -> bool:
    """True when a single label mixes two or more writing systems."""
    return len(scripts_in(text)) > 1


def contains_arabic(text: str) -> bool:
    return bool(_ARABIC_RANGE.search(text or ""))


def normalize_arabic(text: str) -> str:
    """
    Normalise Arabic text for fuzzy keyword matching.

    Removes tashkeel/tatweel and folds common letter variants
    (alef forms, taa marbuta, alef maqsura, kaf/yeh variants).
    """
    if not text:
        return ""
    text = _ARABIC_DIACRITICS.sub("", text)
    table = str.maketrans(
        {
            "أ": "ا",
            "إ": "ا",
            "آ": "ا",
            "ٱ": "ا",
            "ة": "ه",
            "ى": "ي",
            "ئ": "ي",
            "ؤ": "و",
            "گ": "ك",
            "ک": "ك",
            "ی": "ي",
            "ے": "ي",
        }
    )
    return text.translate(table).strip()


def confusable_skeleton(text: str) -> str:
    """
    Collapse look-alike characters to the ASCII letters they imitate.

    ``"nbк"`` (Cyrillic ka) becomes ``"nbk"``; ``"pаypal"`` becomes
    ``"paypal"``. Characters with no mapping are stripped of diacritics
    where possible and otherwise kept.
    """
    if not text:
        return ""
    out = []
    for ch in text.lower():
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        if ch.isascii():
            out.append(ch)
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        ascii_part = "".join(
            c for c in decomposed if c.isascii() and c.isalnum() and not unicodedata.combining(c)
        )
        if ascii_part:
            out.append(ascii_part.lower())
        else:
            out.append(ch)
    return "".join(out)


def leet_normalize(text: str) -> str:
    """Map leetspeak digits/symbols to letters and fold visual sequences."""
    if not text:
        return ""
    mapped = "".join(LEET_MAP.get(ch, ch) for ch in text.lower())
    for seq, repl in VISUAL_SEQUENCES:
        mapped = mapped.replace(seq, repl)
    return mapped


def brand_skeleton(text: str) -> str:
    """Full normalisation used when comparing a label with a brand name."""
    return leet_normalize(confusable_skeleton(text)).replace("-", "").replace("_", "")


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    import math

    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def levenshtein(s1: str, s2: str, max_distance: Optional[int] = None) -> int:
    """
    Levenshtein edit distance with an optional early exit.

    When ``max_distance`` is given and the true distance exceeds it, a value
    greater than ``max_distance`` is returned (exact value not guaranteed).
    """
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)
    if max_distance is not None and len(s1) - len(s2) > max_distance:
        return max_distance + 1

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, start=1):
        curr = [i]
        row_min = i
        for j, c2 in enumerate(s2, start=1):
            cost = 0 if c1 == c2 else 1
            val = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            curr.append(val)
            if val < row_min:
                row_min = val
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
        prev = curr
    return prev[-1]


def similarity(s1: str, s2: str) -> float:
    """Normalised similarity in ``[0, 1]`` based on edit distance."""
    longest = max(len(s1), len(s2))
    if longest == 0:
        return 1.0
    return 1.0 - levenshtein(s1, s2) / longest


def typo_threshold(length: int) -> int:
    """
    Maximum edit distance that still counts as a typo for a label of ``length``.

    Short names such as ``nbk`` or ``kfh`` tolerate a single edit; longer
    names tolerate more, capped at three.
    """
    if length <= 4:
        return 1
    if length <= 8:
        return 2
    return 3


def tokens_of(label: str) -> List[str]:
    """Split a label into word-ish tokens on hyphens, underscores and digits."""
    return [t for t in re.split(r"[-_\d]+", label.lower()) if t]


__all__ = [
    "ALL_MULTI_LABEL_SUFFIXES",
    "CONFUSABLES",
    "FREE_HOSTING_SUFFIXES",
    "GCC_MENA_SUFFIXES",
    "GLOBAL_SUFFIXES",
    "LEET_MAP",
    "ParsedDomain",
    "REGIONAL_SUFFIXES",
    "brand_skeleton",
    "confusable_skeleton",
    "contains_arabic",
    "is_mixed_script",
    "is_subdomain_of",
    "leet_normalize",
    "levenshtein",
    "matches_any",
    "normalize_arabic",
    "normalize_domain",
    "parse_domain",
    "registrable_domain",
    "script_of",
    "scripts_in",
    "shannon_entropy",
    "similarity",
    "split_suffix",
    "to_ascii",
    "to_unicode",
    "tokens_of",
    "typo_threshold",
]
