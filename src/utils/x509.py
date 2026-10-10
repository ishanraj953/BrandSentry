"""
Minimal, dependency-free X.509 / Certificate Transparency parsing.

BrandSentra reads Certificate Transparency logs directly (RFC 6962) instead of
relying on a third-party CertStream server. Each log entry carries a DER-encoded
certificate (or the TBSCertificate of a pre-certificate); this module extracts
the handful of fields the monitor needs: subject CN, DNS SANs, issuer, validity
and serial number. It deliberately implements just enough ASN.1/DER to do that.
"""

from __future__ import annotations

import base64
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

OID_CN = b"\x55\x04\x03"  # 2.5.4.3 commonName
OID_O = b"\x55\x04\x0a"  # 2.5.4.10 organizationName
OID_SAN = b"\x55\x1d\x11"  # 2.5.29.17 subjectAltName
OID_CT_POISON = b"\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x03"  # 1.3.6.1.4.1.11129.2.4.3

TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_OID = 0x06
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


class DERError(ValueError):
    """Raised when the input is not the DER structure we expect."""


def read_tlv(data: bytes, offset: int) -> Tuple[int, int, int, int]:
    """
    Read one DER tag-length-value at ``offset``.

    Returns ``(tag, header_length, value_length, value_offset)``.
    """
    if offset >= len(data):
        raise DERError("unexpected end of data")
    tag = data[offset]
    pos = offset + 1
    if tag & 0x1F == 0x1F:  # multi-byte tag numbers are not used in certificates
        raise DERError("unsupported high tag number")
    if pos >= len(data):
        raise DERError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DERError("invalid long-form length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise DERError("value exceeds buffer")
    return tag, pos - offset, length, pos


def children(data: bytes, offset: int, length: int) -> List[Tuple[int, int, int]]:
    """Return ``(tag, value_offset, value_length)`` for each child of a constructed value."""
    out: List[Tuple[int, int, int]] = []
    end = offset + length
    pos = offset
    while pos < end:
        tag, _hdr, vlen, voff = read_tlv(data, pos)
        out.append((tag, voff, vlen))
        pos = voff + vlen
    return out


def _decode_time(tag: int, raw: bytes) -> Optional[str]:
    text = raw.decode("ascii", "replace")
    try:
        if tag == TAG_UTC_TIME:
            year = int(text[0:2])
            year += 1900 if year >= 50 else 2000
            dt = datetime(
                year,
                int(text[2:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
            )
        elif tag == TAG_GENERALIZED_TIME:
            dt = datetime(
                int(text[0:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                int(text[12:14]) if len(text) >= 14 and text[12:14].isdigit() else 0,
            )
        else:
            return None
    except (ValueError, IndexError):
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat()


def parse_name(data: bytes, offset: int, length: int) -> Dict[str, str]:
    """Parse an X.501 Name into ``{"CN": ..., "O": ...}`` (only those two attributes)."""
    out: Dict[str, str] = {}
    for tag, voff, vlen in children(data, offset, length):
        if tag != TAG_SET:
            continue
        for stag, soff, slen in children(data, voff, vlen):
            if stag != TAG_SEQUENCE:
                continue
            parts = children(data, soff, slen)
            if len(parts) < 2 or parts[0][0] != TAG_OID:
                continue
            oid = data[parts[0][1] : parts[0][1] + parts[0][2]]
            value = data[parts[1][1] : parts[1][1] + parts[1][2]]
            key = "CN" if oid == OID_CN else "O" if oid == OID_O else None
            if key and key not in out:
                out[key] = value.decode("utf-8", "replace")
    return out


def parse_san(data: bytes, offset: int, length: int) -> List[str]:
    """Parse a SubjectAltName extension value (already inside the OCTET STRING)."""
    names: List[str] = []
    tag, _hdr, vlen, voff = read_tlv(data, offset)
    if tag != TAG_SEQUENCE:
        return names
    for gtag, goff, glen in children(data, voff, vlen):
        if gtag == 0x82:  # [2] dNSName
            names.append(data[goff : goff + glen].decode("ascii", "replace").strip().lower())
    return names


def parse_tbs(data: bytes, offset: int, length: int) -> Dict[str, Any]:
    """Parse a TBSCertificate SEQUENCE body."""
    parts = children(data, offset, length)
    idx = 0
    if parts and parts[idx][0] == 0xA0:  # [0] EXPLICIT version
        idx += 1
    if idx >= len(parts) or parts[idx][0] != TAG_INTEGER:
        raise DERError("serial number missing")
    serial = data[parts[idx][1] : parts[idx][1] + parts[idx][2]].hex()
    idx += 1
    idx += 1  # signature algorithm
    if idx + 3 >= len(parts):
        raise DERError("certificate too short")
    issuer = parse_name(data, parts[idx][1], parts[idx][2])
    idx += 1
    validity = children(data, parts[idx][1], parts[idx][2])
    not_before = _decode_time(
        validity[0][0], data[validity[0][1] : validity[0][1] + validity[0][2]]
    )
    not_after = _decode_time(validity[1][0], data[validity[1][1] : validity[1][1] + validity[1][2]])
    idx += 1
    subject = parse_name(data, parts[idx][1], parts[idx][2])
    idx += 1
    dns_names: List[str] = []
    is_precert = False
    for tag, voff, vlen in parts[idx:]:
        if tag != 0xA3:  # [3] EXPLICIT extensions
            continue
        ext_seq = children(data, voff, vlen)
        if not ext_seq:
            continue
        for etag, eoff, elen in children(data, ext_seq[0][1], ext_seq[0][2]):
            if etag != TAG_SEQUENCE:
                continue
            fields = children(data, eoff, elen)
            if not fields or fields[0][0] != TAG_OID:
                continue
            oid = data[fields[0][1] : fields[0][1] + fields[0][2]]
            if oid == OID_CT_POISON:
                is_precert = True
            if oid != OID_SAN:
                continue
            value = fields[-1]
            if value[0] == TAG_OCTET_STRING:
                dns_names = parse_san(data, value[1], value[2])
    cn = subject.get("CN", "").strip().lower()
    all_domains: List[str] = []
    for name in ([cn] if cn else []) + dns_names:
        if name and name not in all_domains:
            all_domains.append(name)
    return {
        "serial_number": serial,
        "issuer": issuer,
        "subject": subject,
        "not_before": not_before,
        "not_after": not_after,
        "all_domains": all_domains,
        "is_precert": is_precert,
    }


def parse_certificate(der: bytes) -> Dict[str, Any]:
    """Parse either a full Certificate or a bare TBSCertificate."""
    tag, _hdr, length, voff = read_tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise DERError("certificate must be a SEQUENCE")
    inner = children(der, voff, length)
    if inner and inner[0][0] == TAG_SEQUENCE:  # Certificate { tbs, sigAlg, signature }
        return parse_tbs(der, inner[0][1], inner[0][2])
    return parse_tbs(der, voff, length)


def parse_leaf_input(leaf_b64: str) -> Dict[str, Any]:
    """
    Parse a CT ``leaf_input`` (MerkleTreeLeaf, RFC 6962 §3.4) from a ``get-entries`` response.

    Returns the parsed certificate fields plus ``entry_type`` (``"x509"`` or ``"precert"``)
    and the log ``timestamp`` in milliseconds.
    """
    raw = base64.b64decode(leaf_b64)
    if len(raw) < 12:
        raise DERError("leaf too short")
    version, leaf_type = raw[0], raw[1]
    if version != 0 or leaf_type != 0:
        raise DERError("unsupported MerkleTreeLeaf")
    timestamp = struct.unpack(">Q", raw[2:10])[0]
    entry_type = struct.unpack(">H", raw[10:12])[0]
    pos = 12
    if entry_type == 0:
        cert_len = int.from_bytes(raw[pos : pos + 3], "big")
        pos += 3
        der = raw[pos : pos + cert_len]
        kind = "x509"
    elif entry_type == 1:
        pos += 32  # issuer_key_hash
        tbs_len = int.from_bytes(raw[pos : pos + 3], "big")
        pos += 3
        der = raw[pos : pos + tbs_len]
        kind = "precert"
    else:
        raise DERError(f"unknown entry type {entry_type}")
    parsed = parse_certificate(der)
    parsed["entry_type"] = kind
    parsed["timestamp"] = timestamp
    return parsed


def to_certstream_message(parsed: Dict[str, Any], log_name: str, index: int) -> Dict[str, Any]:
    """Shape a parsed entry like a CertStream ``certificate_update`` message."""
    return {
        "message_type": "certificate_update",
        "data": {
            "update_type": (
                "PrecertLogEntry" if parsed.get("entry_type") == "precert" else "X509LogEntry"
            ),
            "leaf_cert": {
                "subject": {"CN": parsed.get("subject", {}).get("CN", "")},
                "issuer": parsed.get("issuer", {}),
                "all_domains": parsed.get("all_domains", []),
                "not_before": parsed.get("not_before"),
                "not_after": parsed.get("not_after"),
                "serial_number": parsed.get("serial_number", ""),
                "fingerprint": "",
            },
            "cert_index": index,
            "seen": parsed.get("timestamp", 0) / 1000.0,
            "source": {"name": log_name, "url": ""},
        },
    }


__all__ = [
    "DERError",
    "parse_certificate",
    "parse_leaf_input",
    "parse_name",
    "parse_san",
    "parse_tbs",
    "read_tlv",
    "to_certstream_message",
]


# --------------------------------------------------------------------------- #
# Static CT API (tiled logs): data tiles of TileLeaf structures
# --------------------------------------------------------------------------- #


def parse_tile_leaf(buf: bytes, offset: int = 0) -> Tuple[Dict[str, Any], int]:
    """
    Parse one ``TileLeaf`` from a Static CT API data tile starting at ``offset``.

    Returns ``(parsed_certificate, next_offset)``. The structure is
    ``timestamp(8) entry_type(2) [cert | issuer_key_hash(32) tbs] extensions<2>
    [pre_certificate for precerts] certificate_chain<2 of 32-byte fingerprints>``.
    """
    if offset + 10 > len(buf):
        raise DERError("tile leaf too short")
    timestamp = struct.unpack(">Q", buf[offset : offset + 8])[0]
    entry_type = struct.unpack(">H", buf[offset + 8 : offset + 10])[0]
    pos = offset + 10

    def take(n_len_bytes: int) -> bytes:
        nonlocal pos
        if pos + n_len_bytes > len(buf):
            raise DERError("tile leaf truncated")
        n = int.from_bytes(buf[pos : pos + n_len_bytes], "big")
        pos += n_len_bytes
        if pos + n > len(buf):
            raise DERError("tile leaf truncated")
        chunk = buf[pos : pos + n]
        pos += n
        return chunk

    if entry_type == 0:
        der = take(3)
        kind = "x509"
    elif entry_type == 1:
        pos += 32  # issuer_key_hash
        der = take(3)
        kind = "precert"
    else:
        raise DERError(f"unknown tile entry type {entry_type}")
    take(2)  # extensions
    if entry_type == 1:
        take(3)  # the full pre-certificate (not needed; the TBS carries the names)
    take(2)  # certificate_chain fingerprints
    parsed = parse_certificate(der)
    parsed["entry_type"] = kind
    parsed["timestamp"] = timestamp
    return parsed, pos


def parse_data_tile(buf: bytes) -> List[Dict[str, Any]]:
    """Parse every leaf in a data tile; a malformed leaf ends the tile (entries so far are kept)."""
    out: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(buf):
        parsed, pos = parse_tile_leaf(buf, pos)
        out.append(parsed)
    return out


def tile_path(index: int) -> str:
    """Encode a tile index as the Static CT API path: zero-padded to a multiple of three digits,
    split into 3-digit groups, every group but the last prefixed with ``x``."""
    digits = str(index)
    digits = digits.rjust(((len(digits) + 2) // 3) * 3, "0")
    groups = [digits[i : i + 3] for i in range(0, len(digits), 3)]
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


__all__ += ["parse_data_tile", "parse_tile_leaf", "tile_path"]
