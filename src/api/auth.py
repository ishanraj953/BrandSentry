#!/usr/bin/env python3
"""
BrandSentra - API Authentication

Stateless HMAC-signed bearer tokens plus optional static API keys.

Tokens are ``<base64url(payload)>.<hex hmac-sha256>`` where the payload
carries the username, role, issue and expiry timestamps. Verification is
constant-time and needs no server-side session store, so multiple API
workers can validate tokens issued by any of them as long as they share
``api.secret_key``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

ROLES = ("admin", "analyst", "viewer")


@dataclass
class Principal:
    """Authenticated caller."""

    username: str
    role: str
    method: str  # "token" | "api_key"
    expires_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "auth_method": self.method,
            "expires_at": self.expires_at,
        }

    def has_role(self, *roles: str) -> bool:
        if not roles or self.role == "admin":
            return True
        return self.role in roles


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class TokenAuth:
    """Issue and verify signed bearer tokens."""

    def __init__(self, secret: str, ttl_seconds: int = 28800, now: Callable[[], float] = time.time):
        if not secret:
            raise ValueError("a non-empty secret is required for token signing")
        self._key = hashlib.sha256(secret.encode("utf-8")).digest()
        self.ttl = int(ttl_seconds)
        self._now = now

    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()

    def issue(self, username: str, role: str = "analyst") -> Tuple[str, float]:
        """Return ``(token, expires_at_epoch)``."""
        issued = self._now()
        expires = issued + self.ttl
        payload = _b64encode(
            json.dumps(
                {"u": username, "r": role, "iat": int(issued), "exp": int(expires)},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        return f"{payload}.{self._sign(payload)}", expires

    def verify(self, token: str) -> Optional[Principal]:
        """Return the :class:`Principal` for a valid, unexpired token, else ``None``."""
        if not token or "." not in token:
            return None
        payload, _, signature = token.rpartition(".")
        if not payload or not signature:
            return None
        if not hmac.compare_digest(self._sign(payload), signature):
            return None
        try:
            data = json.loads(_b64decode(payload))
        except (ValueError, UnicodeDecodeError):
            return None
        exp = float(data.get("exp", 0))
        if exp < self._now():
            return None
        role = data.get("r") if data.get("r") in ROLES else "viewer"
        return Principal(str(data.get("u", "")), role, "token", exp)


class UserStore:
    """Static users configured through settings / environment variables."""

    def __init__(self, admin_password: str, analyst_password: str = ""):
        self._users: Dict[str, Tuple[str, str, str]] = {}
        if admin_password:
            self._users["admin"] = (admin_password, "admin", "Administrator")
        if analyst_password:
            self._users["analyst"] = (analyst_password, "analyst", "SOC Analyst")

    def add(self, username: str, password: str, role: str = "analyst", name: str = "") -> None:
        self._users[username] = (password, role if role in ROLES else "analyst", name or username)

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, str]]:
        entry = self._users.get(username or "")
        if not entry:
            hmac.compare_digest("x" * 8, password or "")  # equalise timing
            return None
        stored, role, name = entry
        if not hmac.compare_digest(stored.encode("utf-8"), (password or "").encode("utf-8")):
            return None
        return {"username": username, "role": role, "name": name}

    def __contains__(self, username: str) -> bool:
        return username in self._users


def extract_bearer(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    scheme, _, token = header_value.strip().partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


__all__ = ["Principal", "ROLES", "TokenAuth", "UserStore", "extract_bearer"]
