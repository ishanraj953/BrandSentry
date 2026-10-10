#!/usr/bin/env python3
"""
BrandSentra - Configuration Settings

Central configuration management for all modules.

Resolution order (first hit wins):

1. an explicit path passed to :func:`load_config`,
2. the ``KCW_CONFIG`` environment variable,
3. ``config.local.yaml`` in the working directory (git-ignored, for secrets),
4. ``config.yaml`` in the working directory.

Environment variables prefixed ``KCW_`` override values from the file so
containers and CI can inject secrets without touching YAML.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Dict, List, Mapping, Optional

import yaml

logger = logging.getLogger("brandsentra.config")

DEFAULT_CONFIG_FILES = ("config.local.yaml", "config.yaml")

SEVERITIES = ("critical", "high", "medium", "low", "info")

DEFAULT_SQUAT_TLDS = [
    "com",
    "net",
    "org",
    "co",
    "info",
    "biz",
    "me",
    "io",
    "app",
    "xyz",
    "top",
    "online",
    "site",
    "icu",
    "club",
    "live",
    "shop",
    "cc",
    "link",
    "click",
]


DEFAULT_CERTSTREAM_KEYWORDS: List[str] = [
    "brandsentra",
    "novapay",
    "n0vapay",
    "kestrel",
    "kestrelmart",
    "halcyon",
    "halcyonhealth",
    "meridianbank",
    "apexcloud",
    "luminatelecom",
    "vertexsec",
    "horizonlogistics",
    "secure-login",
    "auth-portal",
    "verify-identity",
    "account-update",
    "payment-gateway",
    "support-desk",
    "onlinebanking",
    "security-alert",
    "signin",
]


@dataclass
class CertStreamConfig:
    """CertStream monitoring configuration."""

    source: str = (
        "ctlogs"  # "ctlogs" = read CT logs directly (no third party), "certstream" = WebSocket
    )
    url: str = "wss://certstream.calidog.io/"  # only used when source == "certstream"
    keywords: List[str] = field(default_factory=lambda: list(DEFAULT_CERTSTREAM_KEYWORDS))
    ct_logs: List[str] = field(
        default_factory=list
    )  # explicit log URLs; empty = discover + fallback
    ct_log_list_url: str = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    ct_batch_size: int = 256
    ct_poll_interval: float = 2.0
    ct_max_lag: int = 5000  # skip ahead when a log outruns us by this many entries
    retry_delay: int = 5
    max_delay: int = 300
    log_file: str = "data/certstream_domains.log"
    heartbeat_interval: int = 100  # persist monitor stats every N certificates
    persist_events: bool = True
    ignore_wildcards: bool = False
    min_keyword_length: int = 3  # keywords shorter than this must match a whole token


@dataclass
class DomainAnalysisConfig:
    """Domain squatting analysis configuration."""

    protected_brands: List[str] = field(
        default_factory=lambda: [
            "novapay.com",
            "kestrelmart.com",
            "halcyonhealth.org",
            "meridianbank.com",
            "apexcloud.io",
            "luminatelecom.com",
            "vertexsecurity.com",
            "horizonlogistics.com",
        ]
    )
    homoglyph_threshold: float = 0.85
    levenshtein_threshold: int = 3  # hard cap; the effective threshold scales with length
    entropy_threshold: float = 3.5
    enable_whois: bool = True
    enable_dns: bool = True
    allowlist: List[str] = field(default_factory=list)
    max_permutations: int = 2000


@dataclass
class NotificationConfig:
    """Notification system configuration."""

    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: List[str] = field(default_factory=list)

    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_channel: str = "#phishing-alerts"

    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_secret: str = ""

    teams_enabled: bool = False
    teams_webhook_url: str = ""

    syslog_enabled: bool = False
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_facility: int = 16

    min_severity: str = "medium"
    cooldown_seconds: int = 3600


@dataclass
class APIConfig:
    """API server configuration."""

    host: str = "0.0.0.0"  # nosec B104 - container friendly default, override in production
    port: int = 5000
    debug: bool = False
    secret_key: str = "change-me-in-production"
    api_key: str = ""
    rate_limit: str = "100/hour"
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    auth_required: bool = False
    admin_password: str = "admin"  # nosec B105 - demo default, override with KCW_ADMIN_PASSWORD
    analyst_password: str = "analyst"  # nosec B105
    token_ttl_seconds: int = 28800
    max_bulk_domains: int = 100
    enable_metrics: bool = True
    trust_proxy: bool = False


@dataclass
class DatabaseConfig:
    """Database configuration."""

    db_type: str = "sqlite"
    db_path: str = "data/brandsentra.db"
    connection_string: str = ""
    retention_days: int = 0  # 0 = keep forever


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration."""

    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    shodan_api_key: str = ""
    abuseipdb_api_key: str = ""
    phishtank_api_key: str = ""
    openphish_enabled: bool = True
    urlhaus_enabled: bool = True
    google_safebrowsing_key: str = ""
    cache_ttl_seconds: int = 3600
    feed_refresh_seconds: int = 3600
    request_timeout: int = 10
    cache_dir: str = "data/intel_cache"


@dataclass
class SquatWatcherConfig:
    """Proactive typosquat discovery configuration."""

    enabled: bool = True
    interval_seconds: int = 21600
    tlds: List[str] = field(default_factory=lambda: list(DEFAULT_SQUAT_TLDS))
    brands: List[str] = field(default_factory=list)  # empty = all protected brands
    include_combos: bool = True
    max_workers: int = 32
    dns_timeout: float = 3.0
    max_candidates_per_brand: int = 1500
    notify_severity: str = "high"


@dataclass
class Settings:
    """Master configuration."""

    certstream: CertStreamConfig = field(default_factory=CertStreamConfig)
    domain_analysis: DomainAnalysisConfig = field(default_factory=DomainAnalysisConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    api: APIConfig = field(default_factory=APIConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    squat_watcher: SquatWatcherConfig = field(default_factory=SquatWatcherConfig)
    brands: List[Dict[str, Any]] = field(default_factory=list)
    brands_replace_defaults: bool = False
    log_level: str = "INFO"
    data_dir: str = "data"
    config_path: Optional[str] = None


# --------------------------------------------------------------------------- #
# Environment overrides
# --------------------------------------------------------------------------- #

#: ``ENV_VAR -> (section or None for top level, field)``
ENV_MAP: Dict[str, tuple] = {
    "KCW_VT_API_KEY": ("threat_intel", "virustotal_api_key"),
    "KCW_URLSCAN_KEY": ("threat_intel", "urlscan_api_key"),
    "KCW_SHODAN_KEY": ("threat_intel", "shodan_api_key"),
    "KCW_ABUSEIPDB_KEY": ("threat_intel", "abuseipdb_api_key"),
    "KCW_PHISHTANK_KEY": ("threat_intel", "phishtank_api_key"),
    "KCW_GSB_KEY": ("threat_intel", "google_safebrowsing_key"),
    "KCW_SLACK_WEBHOOK": ("notifications", "slack_webhook_url"),
    "KCW_TELEGRAM_TOKEN": ("notifications", "telegram_bot_token"),
    "KCW_TELEGRAM_CHAT": ("notifications", "telegram_chat_id"),
    "KCW_TEAMS_WEBHOOK": ("notifications", "teams_webhook_url"),
    "KCW_WEBHOOK_URL": ("notifications", "webhook_url"),
    "KCW_WEBHOOK_SECRET": ("notifications", "webhook_secret"),
    "KCW_SMTP_PASSWORD": ("notifications", "email_password"),
    "KCW_MIN_SEVERITY": ("notifications", "min_severity"),
    "KCW_API_SECRET": ("api", "secret_key"),
    "KCW_API_KEY": ("api", "api_key"),
    "KCW_API_HOST": ("api", "host"),
    "KCW_API_PORT": ("api", "port"),
    "KCW_RATE_LIMIT": ("api", "rate_limit"),
    "KCW_AUTH_REQUIRED": ("api", "auth_required"),
    "KCW_ADMIN_PASSWORD": ("api", "admin_password"),
    "KCW_ANALYST_PASSWORD": ("api", "analyst_password"),
    "KCW_DB_PATH": ("database", "db_path"),
    "KCW_CERTSTREAM_URL": ("certstream", "url"),
    "KCW_CERTSTREAM_SOURCE": ("certstream", "source"),
    "KCW_LOG_LEVEL": (None, "log_level"),
    "KCW_DATA_DIR": (None, "data_dir"),
}

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f", ""}


def _coerce(value: Any, target_type: Any, current: Any) -> Any:
    """Coerce a YAML / environment value to the type of the dataclass field."""
    if value is None:
        return current
    type_name = getattr(target_type, "__name__", str(target_type))
    origin = getattr(target_type, "__origin__", None)

    if target_type is bool or type_name == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
        raise ValueError(f"cannot interpret {value!r} as boolean")
    if target_type is int or type_name == "int":
        return int(value)
    if target_type is float or type_name == "float":
        return float(value)
    if target_type is str or type_name == "str":
        return str(value)
    if origin is list or type_name in ("List", "list") or str(target_type).startswith("List["):
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]
    if str(target_type).startswith("Optional[str]"):
        return None if value is None else str(value)
    return value


def _apply_mapping(target: Any, data: Mapping[str, Any], path: str) -> None:
    """Apply ``data`` onto dataclass ``target`` with coercion; unknown keys are logged."""
    if not isinstance(data, Mapping):
        logger.warning("Config section %s must be a mapping, got %s", path, type(data).__name__)
        return
    known = {f.name: f for f in fields(target)}
    for key, value in data.items():
        if key not in known:
            logger.debug("Ignoring unknown config key %s.%s", path, key)
            continue
        current = getattr(target, key)
        try:
            setattr(target, key, _coerce(value, known[key].type, current))
        except (TypeError, ValueError) as exc:
            logger.warning("Invalid value for %s.%s (%r): %s", path, key, value, exc)


def find_config_path(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve which configuration file to load, or ``None`` for pure defaults."""
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("KCW_CONFIG")
    if env_path:
        candidates.append(env_path)
    candidates.extend(DEFAULT_CONFIG_FILES)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def load_yaml(path: str) -> Dict[str, Any]:
    """Read a YAML mapping from ``path`` (empty file -> ``{}``)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return data


def apply_dict(settings: Settings, data: Mapping[str, Any]) -> Settings:
    """Merge a configuration mapping into ``settings`` (in place) and return it."""
    section_names = {f.name for f in fields(Settings) if is_dataclass(getattr(settings, f.name))}
    for key, value in data.items():
        if key in section_names:
            _apply_mapping(getattr(settings, key), value or {}, key)
        elif key == "brands":
            settings.brands = list(value or [])
        elif key == "brands_replace_defaults":
            settings.brands_replace_defaults = _coerce(value, bool, False)
        elif key == "log_level":
            settings.log_level = str(value).upper()
        elif key == "data_dir":
            settings.data_dir = str(value)
        else:
            logger.debug("Ignoring unknown top-level config key %s", key)
    return settings


def apply_env_overrides(
    settings: Settings, environ: Optional[Mapping[str, str]] = None
) -> Settings:
    """Apply ``KCW_*`` environment overrides to ``settings`` in place."""
    env = os.environ if environ is None else environ
    for env_var, (section, key) in ENV_MAP.items():
        raw = env.get(env_var)
        if raw is None or raw == "":
            continue
        target = settings if section is None else getattr(settings, section)
        field_type = {f.name: f.type for f in fields(target)}[key]
        try:
            setattr(target, key, _coerce(raw, field_type, getattr(target, key)))
        except (TypeError, ValueError) as exc:
            logger.warning("Ignoring invalid %s=%r: %s", env_var, raw, exc)
    return settings


def load_config(config_path: Optional[str] = None) -> Settings:
    """Load configuration from YAML (if found) with environment overrides."""
    settings = Settings()
    path = find_config_path(config_path)
    if config_path and path != config_path:
        logger.warning("Config file %s not found; falling back to %s", config_path, path)
    if path:
        try:
            apply_dict(settings, load_yaml(path))
            settings.config_path = path
        except (OSError, ValueError, yaml.YAMLError) as exc:
            logger.error("Failed to load config %s: %s", path, exc)
    apply_env_overrides(settings)
    return settings


# --------------------------------------------------------------------------- #
# Introspection helpers
# --------------------------------------------------------------------------- #

SECRET_HINTS = ("key", "secret", "password", "token", "webhook")


def _redact(name: str, value: Any) -> Any:
    lowered = name.lower()
    if any(h in lowered for h in SECRET_HINTS) and isinstance(value, str) and value:
        return "***"
    return value


def to_dict(settings: Settings, redact: bool = True) -> Dict[str, Any]:
    """Serialise settings to plain dicts, masking secrets unless ``redact`` is False."""
    result: Dict[str, Any] = {}
    for f in fields(settings):
        value = getattr(settings, f.name)
        if is_dataclass(value):
            section = dataclasses.asdict(value)
            if redact:
                section = {k: _redact(k, v) for k, v in section.items()}
            result[f.name] = section
        else:
            result[f.name] = value
    return result


def validate(settings: Settings) -> List[str]:
    """Return a list of human-readable warnings about risky or inconsistent settings."""
    warnings: List[str] = []
    api = settings.api
    notif = settings.notifications

    if api.secret_key == "change-me-in-production":
        warnings.append("api.secret_key is the default value; set KCW_API_SECRET")
    if api.admin_password == "admin":
        warnings.append("api.admin_password is the demo default; set KCW_ADMIN_PASSWORD")
    if api.auth_required and not api.api_key and api.admin_password == "admin":
        warnings.append("api.auth_required is on but only the demo password protects it")
    if api.debug:
        warnings.append("api.debug is enabled; never expose a debug server publicly")
    if "*" in api.cors_origins and api.auth_required:
        warnings.append("api.cors_origins allows any origin while authentication is required")
    if notif.min_severity not in SEVERITIES:
        warnings.append(f"notifications.min_severity {notif.min_severity!r} is not a severity")
    if notif.syslog_protocol.lower() not in ("udp", "tcp"):
        warnings.append("notifications.syslog_protocol must be 'udp' or 'tcp'")

    channel_requirements = {
        "slack": (notif.slack_enabled, notif.slack_webhook_url),
        "telegram": (notif.telegram_enabled, notif.telegram_bot_token and notif.telegram_chat_id),
        "webhook": (notif.webhook_enabled, notif.webhook_url),
        "teams": (notif.teams_enabled, notif.teams_webhook_url),
        "email": (notif.email_enabled, notif.email_smtp_server and notif.email_recipients),
    }
    for name, (enabled, configured) in channel_requirements.items():
        if enabled and not configured:
            warnings.append(f"notifications.{name}_enabled is on but the channel is not configured")

    if settings.squat_watcher.interval_seconds < 300:
        warnings.append("squat_watcher.interval_seconds under 300 will hammer DNS resolvers")
    if not settings.domain_analysis.protected_brands:
        warnings.append("domain_analysis.protected_brands is empty; squatting checks are disabled")
    return warnings


__all__ = [
    "APIConfig",
    "CertStreamConfig",
    "DatabaseConfig",
    "DEFAULT_SQUAT_TLDS",
    "DomainAnalysisConfig",
    "ENV_MAP",
    "NotificationConfig",
    "SEVERITIES",
    "Settings",
    "SquatWatcherConfig",
    "ThreatIntelConfig",
    "apply_dict",
    "apply_env_overrides",
    "find_config_path",
    "load_config",
    "load_yaml",
    "to_dict",
    "validate",
]
