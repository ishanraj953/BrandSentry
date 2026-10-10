#!/usr/bin/env python3
"""
BrandSentra - Notification Dispatcher
Sends alerts via Email, Slack, Telegram, Microsoft Teams, Syslog (CEF) and Webhooks,
with severity filtering and duplicate-alert throttling.
"""

import json
import logging
import smtplib
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Callable, Dict, List, Optional, Tuple

from src import __version__

logger = logging.getLogger("brandsentra.notifications")

#: Numeric ranking of alert severities (higher is more severe).
SEVERITY_ORDER: Dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def severity_rank(severity: str) -> int:
    """Return the numeric rank of a severity label.

    Args:
        severity: Severity label such as ``"critical"`` or ``"low"``. Matching is
            case-insensitive.

    Returns:
        The rank from :data:`SEVERITY_ORDER`, or ``0`` for unknown labels.
    """
    return SEVERITY_ORDER.get(str(severity).lower(), 0)


@dataclass
class Alert:
    """Notification alert payload."""

    title: str
    message: str
    severity: str  # critical, high, medium, low
    domain: str
    alert_type: str
    details: Dict
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def severity_rank(self) -> int:
        """Numeric rank of this alert's severity (see :func:`severity_rank`)."""
        return severity_rank(self.severity)

    def to_dict(self) -> Dict:
        """Serialise the alert to a plain dictionary.

        Returns:
            A JSON-serialisable dictionary with all alert fields.
        """
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "domain": self.domain,
            "alert_type": self.alert_type,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class AlertThrottle:
    """Suppress repeated alerts for the same domain and alert type.

    The throttle remembers when an alert keyed by ``(domain, alert_type)`` was last
    allowed through and rejects repeats until ``cooldown_seconds`` have elapsed.

    Attributes:
        cooldown_seconds: Minimum number of seconds between two alerts with the same key.
        max_entries: Upper bound on remembered keys; older entries are evicted beyond it.
        suppressed: Running count of alerts rejected by :meth:`should_send`.
    """

    def __init__(
        self,
        cooldown_seconds: int = 3600,
        now: Callable[[], float] = time.time,
        max_entries: int = 10000,
    ):
        """Initialise the throttle.

        Args:
            cooldown_seconds: Cooldown window in seconds. ``0`` disables throttling.
            now: Clock function returning the current time in seconds; injectable for tests.
            max_entries: Maximum number of keys to remember before evicting the oldest.
        """
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self.max_entries = max(1, int(max_entries))
        self.suppressed = 0
        self._now = now
        self._last_sent: Dict[Tuple[str, str], float] = {}

    @staticmethod
    def key_for(alert: Alert) -> Tuple[str, str]:
        """Return the throttle key for an alert.

        Args:
            alert: The alert to derive a key for.

        Returns:
            A ``(domain, alert_type)`` tuple with the domain lower-cased.
        """
        return (str(alert.domain or "").lower(), str(alert.alert_type or ""))

    def should_send(self, alert: Alert) -> bool:
        """Decide whether an alert may be sent and record it if so.

        Args:
            alert: The alert about to be dispatched.

        Returns:
            ``True`` on first sight of the key or once the cooldown has elapsed, in which
            case the current time is recorded; ``False`` if the alert is a duplicate
            inside the cooldown window (``suppressed`` is incremented).
        """
        key = self.key_for(alert)
        now = self._now()
        last = self._last_sent.get(key)
        if last is not None and (now - last) < self.cooldown_seconds:
            self.suppressed += 1
            return False
        self._last_sent[key] = now
        if len(self._last_sent) > self.max_entries:
            self.purge()
        return True

    def purge(self) -> int:
        """Drop expired entries and, if still over ``max_entries``, the oldest ones.

        Returns:
            The number of entries removed.
        """
        now = self._now()
        expired = [
            key for key, seen in self._last_sent.items() if (now - seen) >= self.cooldown_seconds
        ]
        for key in expired:
            del self._last_sent[key]
        removed = len(expired)

        overflow = len(self._last_sent) - self.max_entries
        if overflow > 0:
            oldest = sorted(self._last_sent.items(), key=lambda item: item[1])[:overflow]
            for key, _ in oldest:
                del self._last_sent[key]
            removed += overflow
        return removed

    def __len__(self) -> int:
        return len(self._last_sent)


class EmailNotifier:
    """Send alerts via SMTP email."""

    def __init__(self, config):
        self.server = config.email_smtp_server
        self.port = config.email_smtp_port
        self.username = config.email_username
        self.password = config.email_password
        self.recipients = config.email_recipients

    def send(self, alert: Alert) -> bool:
        if not self.server:
            logger.warning("Email not configured")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[BrandSentra] [{alert.severity.upper()}] {alert.title}"
            msg["From"] = self.username
            msg["To"] = ", ".join(self.recipients)

            html = f"""
            <html><body style="font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#16213e;border-radius:8px;padding:24px;border-left:4px solid {'#ff4444' if alert.severity == 'critical' else '#ff8800' if alert.severity == 'high' else '#ffcc00'};">
            <h2 style="color:#aa95f9;margin-top:0;">🚨 BrandSentra Alert</h2>
            <p><strong>Severity:</strong> <span style="color:{'#ff4444' if alert.severity == 'critical' else '#ff8800'};">{alert.severity.upper()}</span></p>
            <p><strong>Domain:</strong> <code style="background:#0f3460;padding:2px 6px;border-radius:3px;">{alert.domain}</code></p>
            <p><strong>Type:</strong> {alert.alert_type}</p>
            <p><strong>Details:</strong> {alert.message}</p>
            <hr style="border-color:#0f3460;">
            <p style="font-size:12px;color:#888;">BrandSentra Digital Risk Protection Suite | {alert.timestamp}</p>
            </div></body></html>
            """

            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.server, self.port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, self.recipients, msg.as_string())

            logger.info(f"Email sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False


class SlackNotifier:
    """Send alerts to Slack via webhook."""

    def __init__(self, config):
        self.webhook_url = config.slack_webhook_url
        self.channel = config.slack_channel

    def send(self, alert: Alert) -> bool:
        if not self.webhook_url:
            logger.warning("Slack not configured")
            return False
        try:
            import requests

            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
            emoji = severity_emoji.get(alert.severity, "⚪")

            payload = {
                "channel": self.channel,
                "username": "BrandSentra",
                "icon_emoji": ":shield:",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"{emoji} {alert.title}"},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Domain:*\n`{alert.domain}`"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{alert.alert_type}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{alert.timestamp}"},
                        ],
                    },
                    {"type": "section", "text": {"type": "mrkdwn", "text": alert.message}},
                ],
            }

            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info(f"Slack notification sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False


class TelegramNotifier:
    """Send alerts via Telegram Bot API."""

    def __init__(self, config):
        self.token = config.telegram_bot_token
        self.chat_id = config.telegram_chat_id

    def send(self, alert: Alert) -> bool:
        if not self.token or not self.chat_id:
            logger.warning("Telegram not configured")
            return False
        try:
            import requests

            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
            emoji = severity_emoji.get(alert.severity, "⚪")

            text = (
                f"{emoji} *BrandSentra Alert*\n\n"
                f"*{alert.title}*\n"
                f"Severity: `{alert.severity.upper()}`\n"
                f"Domain: `{alert.domain}`\n"
                f"Type: {alert.alert_type}\n\n"
                f"{alert.message}\n\n"
                f"_{alert.timestamp}_"
            )

            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            resp = requests.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            resp.raise_for_status()
            logger.info(f"Telegram notification sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False


class WebhookNotifier:
    """Send alerts to generic webhook endpoints."""

    def __init__(self, config):
        self.url = config.webhook_url
        self.secret = config.webhook_secret

    def send(self, alert: Alert) -> bool:
        if not self.url:
            logger.warning("Webhook not configured")
            return False
        try:
            import hmac

            import requests

            payload = json.dumps(alert.to_dict())
            headers = {"Content-Type": "application/json"}
            if self.secret:
                sig = hmac.new(self.secret.encode(), payload.encode(), "sha256").hexdigest()
                headers["X-KCW-Signature"] = sig

            resp = requests.post(self.url, data=payload, headers=headers, timeout=10)
            resp.raise_for_status()
            logger.info(f"Webhook sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Webhook send failed: {e}")
            return False


class TeamsNotifier:
    """Send alerts to Microsoft Teams via an Office 365 connector webhook."""

    #: MessageCard ``themeColor`` (hex, no ``#``) per severity.
    THEME_COLORS: Dict[str, str] = {
        "critical": "FF3355",
        "high": "FF8C00",
        "medium": "FFD600",
        "low": "00E676",
    }
    DEFAULT_THEME_COLOR = "00D4FF"

    def __init__(self, config):
        """Initialise the notifier.

        Args:
            config: Notification settings exposing ``teams_webhook_url``.
        """
        self.webhook_url = getattr(config, "teams_webhook_url", "") or ""

    def build_payload(self, alert: Alert) -> Dict:
        """Build the Office 365 connector MessageCard for an alert.

        Args:
            alert: The alert to render.

        Returns:
            A MessageCard dictionary ready to be posted as JSON.
        """
        severity = str(alert.severity or "").lower()
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": self.THEME_COLORS.get(severity, self.DEFAULT_THEME_COLOR),
            "summary": alert.title,
            "sections": [
                {
                    "activityTitle": f"🛡️ BrandSentra — {alert.title}",
                    "activitySubtitle": alert.timestamp,
                    "facts": [
                        {"name": "Severity", "value": str(alert.severity).upper()},
                        {"name": "Domain", "value": alert.domain},
                        {"name": "Type", "value": alert.alert_type},
                    ],
                    "markdown": True,
                    "text": alert.message,
                }
            ],
        }

    def send(self, alert: Alert) -> bool:
        """POST the MessageCard to the configured Teams webhook.

        Args:
            alert: The alert to send.

        Returns:
            ``True`` if Teams accepted the card, ``False`` when unconfigured or on error.
        """
        if not self.webhook_url:
            logger.warning("Teams not configured")
            return False
        try:
            import requests

            resp = requests.post(self.webhook_url, json=self.build_payload(alert), timeout=10)
            resp.raise_for_status()
            logger.info(f"Teams notification sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Teams send failed: {e}")
            return False


class SyslogNotifier:
    """Send alerts to a SIEM as RFC 3164 syslog messages carrying ArcSight CEF."""

    CEF_VENDOR = "BrandSentra"
    CEF_PRODUCT = "BrandSentra"
    SYSLOG_TAG = "brandsentra"
    #: CEF severity (0-10) per alert severity.
    CEF_SEVERITY: Dict[str, int] = {"critical": 10, "high": 8, "medium": 5, "low": 3}
    DEFAULT_CEF_SEVERITY = 1
    #: Syslog severity level per alert severity (RFC 5424 numerical codes).
    SYSLOG_SEVERITY: Dict[str, int] = {"critical": 2, "high": 3, "medium": 4, "low": 6}
    DEFAULT_SYSLOG_SEVERITY = 5
    TCP_TIMEOUT = 5

    def __init__(self, config):
        """Initialise the notifier.

        Args:
            config: Notification settings exposing ``syslog_enabled``, ``syslog_host``,
                ``syslog_port``, ``syslog_protocol`` (``"udp"`` or ``"tcp"``) and
                ``syslog_facility``.
        """
        self.enabled = bool(getattr(config, "syslog_enabled", False))
        self.host = getattr(config, "syslog_host", "127.0.0.1") or ""
        self.port = int(getattr(config, "syslog_port", 514) or 0)
        self.protocol = str(getattr(config, "syslog_protocol", "udp") or "udp").lower()
        self.facility = int(getattr(config, "syslog_facility", 16))

    @staticmethod
    def escape_header(value: Any) -> str:
        """Escape a CEF header field (``\\`` and ``|``)."""
        return str(value).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def escape_extension(value: Any) -> str:
        """Escape a CEF extension value (``\\``, ``=`` and newlines)."""
        text = str(value).replace("\\", "\\\\").replace("=", "\\=")
        return text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")

    @staticmethod
    def _epoch_ms(timestamp: str) -> int:
        """Convert an ISO-8601 timestamp to epoch milliseconds (now on parse failure)."""
        try:
            text = str(timestamp).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp() * 1000)
        except (TypeError, ValueError):
            return int(time.time() * 1000)

    def cef_severity(self, severity: str) -> int:
        """Map an alert severity to the CEF 0-10 severity scale."""
        return self.CEF_SEVERITY.get(str(severity).lower(), self.DEFAULT_CEF_SEVERITY)

    def syslog_severity(self, severity: str) -> int:
        """Map an alert severity to a syslog severity level."""
        return self.SYSLOG_SEVERITY.get(str(severity).lower(), self.DEFAULT_SYSLOG_SEVERITY)

    def build_cef(self, alert: Alert) -> str:
        """Render an alert as an ArcSight CEF event string.

        Args:
            alert: The alert to render.

        Returns:
            A ``CEF:0|...`` line with header fields and a key/value extension.
        """
        header = "|".join(
            [
                "CEF:0",
                self.escape_header(self.CEF_VENDOR),
                self.escape_header(self.CEF_PRODUCT),
                self.escape_header(__version__),
                self.escape_header(alert.alert_type),
                self.escape_header(alert.title),
                str(self.cef_severity(alert.severity)),
            ]
        )
        details_json = json.dumps(
            alert.details or {}, separators=(",", ":"), default=str, ensure_ascii=False
        )
        extension = " ".join(
            [
                f"dhost={self.escape_extension(alert.domain)}",
                f"cat={self.escape_extension(alert.severity)}",
                f"rt={self._epoch_ms(alert.timestamp)}",
                f"msg={self.escape_extension(alert.message)}",
                "cs1Label=alertType",
                f"cs1={self.escape_extension(alert.alert_type)}",
                "cs2Label=details",
                f"cs2={self.escape_extension(details_json)}",
            ]
        )
        return f"{header}|{extension}"

    def build_syslog_message(self, alert: Alert) -> str:
        """Wrap the CEF event in an RFC 3164 syslog envelope.

        Args:
            alert: The alert to render.

        Returns:
            ``<PRI>Mon dd HH:MM:SS hostname brandsentra: CEF:0|...``.
        """
        pri = self.facility * 8 + self.syslog_severity(alert.severity)
        now = datetime.now()
        stamp = f"{now:%b} {now.day:2d} {now:%H:%M:%S}"
        hostname = socket.gethostname()
        return f"<{pri}>{stamp} {hostname} {self.SYSLOG_TAG}: {self.build_cef(alert)}"

    def send(self, alert: Alert) -> bool:
        """Send the alert to the syslog collector over UDP or TCP.

        Args:
            alert: The alert to send.

        Returns:
            ``True`` when the datagram/stream write succeeded, ``False`` when the notifier
            is disabled, unconfigured, or the socket operation failed.
        """
        if not self.enabled:
            logger.warning("Syslog not enabled")
            return False
        if not self.host or not self.port:
            logger.warning("Syslog not configured")
            return False

        sock = None
        try:
            message = self.build_syslog_message(alert)
            if self.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.TCP_TIMEOUT)
                sock.connect((self.host, self.port))
                sock.sendall((message + "\n").encode("utf-8"))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode("utf-8"), (self.host, self.port))
            logger.info(f"Syslog event sent ({self.protocol}): {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Syslog send failed: {e}")
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # pragma: no cover - best-effort cleanup
                    pass


class NotificationDispatcher:
    """Central dispatcher that routes alerts to all configured channels.

    Alerts below ``min_severity`` are dropped and repeated alerts for the same
    ``(domain, alert_type)`` are throttled, unless ``force=True`` is passed.

    Attributes:
        notifiers: ``(channel_name, notifier)`` pairs built from the config.
        min_severity: Lowest severity label that is dispatched.
        throttle: The :class:`AlertThrottle` used for duplicate suppression.
        stats: Counters for dispatched/sent/failed/suppressed alerts and per-channel totals.
    """

    def __init__(self, config, throttle: Optional[AlertThrottle] = None):
        """Build notifiers for every enabled channel.

        Args:
            config: Notification settings dataclass. New attributes are read with
                defaults so older configs keep working.
            throttle: Optional pre-built throttle; one is created from
                ``config.cooldown_seconds`` when omitted.
        """
        self.notifiers: List[Tuple[str, Any]] = []
        if getattr(config, "email_enabled", False):
            self.notifiers.append(("email", EmailNotifier(config)))
        if getattr(config, "slack_enabled", False):
            self.notifiers.append(("slack", SlackNotifier(config)))
        if getattr(config, "telegram_enabled", False):
            self.notifiers.append(("telegram", TelegramNotifier(config)))
        if getattr(config, "webhook_enabled", False):
            self.notifiers.append(("webhook", WebhookNotifier(config)))
        if getattr(config, "teams_enabled", False):
            self.notifiers.append(("teams", TeamsNotifier(config)))
        if getattr(config, "syslog_enabled", False):
            self.notifiers.append(("syslog", SyslogNotifier(config)))

        self.min_severity = str(getattr(config, "min_severity", "medium") or "medium").lower()
        cooldown = int(getattr(config, "cooldown_seconds", 3600))
        # ``AlertThrottle`` defines ``__len__``; an empty one is falsy, so test identity.
        self.throttle = throttle if throttle is not None else AlertThrottle(cooldown)
        self.stats: Dict[str, Any] = {
            "dispatched": 0,
            "sent": 0,
            "failed": 0,
            "suppressed_severity": 0,
            "suppressed_duplicate": 0,
            "per_channel": {name: {"sent": 0, "failed": 0} for name, _ in self.notifiers},
        }

    @property
    def channels(self) -> List[str]:
        """Names of the configured notification channels, in dispatch order."""
        return [name for name, _ in self.notifiers]

    def dispatch(self, alert: Alert, force: bool = False) -> Dict[str, bool]:
        """Send alert to all configured notification channels.

        Args:
            alert: The alert to send.
            force: Skip severity filtering and duplicate throttling when ``True``.

        Returns:
            Mapping of channel name to send success. Empty when the alert was suppressed.
        """
        if not force and severity_rank(alert.severity) < severity_rank(self.min_severity):
            self.stats["suppressed_severity"] += 1
            logger.debug(
                f"Alert suppressed by severity ({alert.severity} < {self.min_severity}): "
                f"{alert.title}"
            )
            return {}
        if not force and not self.throttle.should_send(alert):
            self.stats["suppressed_duplicate"] += 1
            logger.debug(f"Alert suppressed as duplicate: {alert.domain}/{alert.alert_type}")
            return {}

        self.stats["dispatched"] += 1
        results: Dict[str, bool] = {}
        for name, notifier in self.notifiers:
            try:
                ok = bool(notifier.send(alert))
            except Exception as e:  # notifiers catch their own errors; this is a safety net
                logger.error(f"{name} notifier raised: {e}")
                ok = False
            results[name] = ok
            channel = self.stats["per_channel"].setdefault(name, {"sent": 0, "failed": 0})
            if ok:
                self.stats["sent"] += 1
                channel["sent"] += 1
            else:
                self.stats["failed"] += 1
                channel["failed"] += 1
        return results

    def dispatch_critical(self, alert: Alert) -> Dict[str, bool]:
        """Force-send to all channels regardless of severity filtering."""
        alert.severity = "critical"
        return self.dispatch(alert, force=True)

    def test_channels(self) -> Dict[str, bool]:
        """Send a synthetic low-severity test alert to every channel, bypassing filters.

        Returns:
            Mapping of channel name to send success.
        """
        alert = Alert(
            title="BrandSentra test alert",
            message="This is a test notification from BrandSentra. No action is required.",
            severity="low",
            domain="example.com",
            alert_type="test",
            details={"test": True, "version": __version__},
        )
        return self.dispatch(alert, force=True)
