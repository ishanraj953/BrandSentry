#!/usr/bin/env python3
"""
BrandSentra - Notification dispatcher tests.

All tests run offline: HTTP calls are intercepted by patching ``requests.post`` and
syslog traffic by patching ``socket.socket``.
"""

import hmac
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import List
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import __version__  # noqa: E402
from src.notifications.dispatcher import (  # noqa: E402
    SEVERITY_ORDER,
    Alert,
    AlertThrottle,
    EmailNotifier,
    NotificationDispatcher,
    SlackNotifier,
    SyslogNotifier,
    TeamsNotifier,
    TelegramNotifier,
    WebhookNotifier,
    severity_rank,
)

TEAMS_URL = "https://outlook.office.com/webhook/abc"
SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXX"
WEBHOOK_URL = "https://siem.example.kw/hook"


def make_config(**overrides) -> SimpleNamespace:
    """Return a notification config namespace with every channel disabled."""
    base = dict(
        email_enabled=False,
        email_smtp_server="",
        email_smtp_port=587,
        email_username="",
        email_password="",
        email_recipients=[],
        slack_enabled=False,
        slack_webhook_url="",
        slack_channel="#phishing-alerts",
        telegram_enabled=False,
        telegram_bot_token="",
        telegram_chat_id="",
        webhook_enabled=False,
        webhook_url="",
        webhook_secret="",
        min_severity="medium",
        cooldown_seconds=3600,
        teams_enabled=False,
        teams_webhook_url="",
        syslog_enabled=False,
        syslog_host="127.0.0.1",
        syslog_port=514,
        syslog_protocol="udp",
        syslog_facility=16,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def make_alert(**overrides) -> Alert:
    """Return a representative high-severity phishing alert."""
    fields = dict(
        title="Phishing domain detected",
        message="Lookalike of nbk.com registered",
        severity="high",
        domain="nbk-secure-login.com",
        alert_type="phishing_domain",
        details={"score": 87, "brand": "NBK"},
        timestamp="2026-01-02T03:04:05+00:00",
    )
    fields.update(overrides)
    return Alert(**fields)


class FakeClock:
    """Deterministic clock for throttle tests."""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeNotifier:
    """Notifier stub that records alerts and returns a configurable result."""

    def __init__(self, result: bool = True):
        self.result = result
        self.alerts: List[Alert] = []

    def send(self, alert: Alert) -> bool:
        self.alerts.append(alert)
        return self.result


def ok_response() -> MagicMock:
    """Return a mock HTTP response whose ``raise_for_status`` is a no-op."""
    resp = MagicMock()
    resp.status_code = 200
    return resp


# --------------------------------------------------------------------------- severity


class TestSeverity:
    def test_severity_rank_known_and_unknown(self):
        assert severity_rank("critical") == 4
        assert severity_rank("HIGH") == 3
        assert severity_rank("medium") == 2
        assert severity_rank("low") == 1
        assert severity_rank("info") == 0
        assert severity_rank("bogus") == 0
        assert severity_rank("") == 0
        assert SEVERITY_ORDER["critical"] > SEVERITY_ORDER["high"] > SEVERITY_ORDER["low"]

    def test_alert_severity_rank_property_and_to_dict(self):
        alert = make_alert(severity="critical")
        assert alert.severity_rank == 4
        data = alert.to_dict()
        assert data["severity"] == "critical"
        assert data["domain"] == "nbk-secure-login.com"
        assert data["details"] == {"score": 87, "brand": "NBK"}
        assert data["timestamp"] == "2026-01-02T03:04:05+00:00"
        assert Alert("t", "m", "low", "d", "x", {}).timestamp  # auto-filled


# --------------------------------------------------------------------------- throttle


class TestAlertThrottle:
    def test_first_sight_is_allowed_and_recorded(self):
        throttle = AlertThrottle(cooldown_seconds=60, now=FakeClock())
        assert throttle.should_send(make_alert()) is True
        assert len(throttle) == 1
        assert throttle.suppressed == 0

    def test_duplicate_inside_cooldown_is_suppressed(self):
        clock = FakeClock()
        throttle = AlertThrottle(cooldown_seconds=60, now=clock)
        assert throttle.should_send(make_alert()) is True
        clock.advance(30)
        assert throttle.should_send(make_alert()) is False
        assert throttle.suppressed == 1
        # Domain matching is case-insensitive; alert_type is part of the key.
        assert throttle.should_send(make_alert(domain="NBK-SECURE-LOGIN.COM")) is False
        assert throttle.should_send(make_alert(alert_type="typosquat")) is True
        assert throttle.suppressed == 2

    def test_allowed_again_after_cooldown(self):
        clock = FakeClock()
        throttle = AlertThrottle(cooldown_seconds=60, now=clock)
        assert throttle.should_send(make_alert()) is True
        clock.advance(60)
        assert throttle.should_send(make_alert()) is True
        clock.advance(59)
        assert throttle.should_send(make_alert()) is False
        assert throttle.key_for(make_alert()) == ("nbk-secure-login.com", "phishing_domain")

    def test_purge_drops_expired_then_oldest(self):
        clock = FakeClock()
        throttle = AlertThrottle(cooldown_seconds=100, now=clock, max_entries=2)
        throttle.should_send(make_alert(domain="a.com"))
        clock.advance(10)
        throttle.should_send(make_alert(domain="b.com"))
        clock.advance(10)
        # Third insert exceeds max_entries -> automatic purge evicts the oldest (a.com).
        throttle.should_send(make_alert(domain="c.com"))
        assert len(throttle) == 2
        assert throttle.should_send(make_alert(domain="a.com")) is True

        clock.advance(200)  # everything is now expired
        assert throttle.purge() == 2
        assert len(throttle) == 0


# --------------------------------------------------------------------------- teams


class TestTeamsNotifier:
    def test_build_payload_fields(self):
        alert = make_alert(severity="critical")
        payload = TeamsNotifier(make_config(teams_webhook_url=TEAMS_URL)).build_payload(alert)
        assert payload["@type"] == "MessageCard"
        assert payload["@context"] == "https://schema.org/extensions"
        assert payload["themeColor"] == "FF3355"
        assert payload["summary"] == alert.title
        section = payload["sections"][0]
        assert section["activityTitle"] == f"🛡️ BrandSentra — {alert.title}"
        assert section["activitySubtitle"] == alert.timestamp
        assert section["markdown"] is True
        assert section["text"] == alert.message
        facts = {f["name"]: f["value"] for f in section["facts"]}
        assert facts == {
            "Severity": "CRITICAL",
            "Domain": alert.domain,
            "Type": alert.alert_type,
        }

    @pytest.mark.parametrize(
        "severity,color",
        [
            ("critical", "FF3355"),
            ("high", "FF8C00"),
            ("medium", "FFD600"),
            ("low", "00E676"),
            ("info", "00D4FF"),
            ("weird", "00D4FF"),
        ],
    )
    def test_theme_color_by_severity(self, severity, color):
        notifier = TeamsNotifier(make_config(teams_webhook_url=TEAMS_URL))
        assert notifier.build_payload(make_alert(severity=severity))["themeColor"] == color

    def test_send_posts_json_to_webhook(self):
        notifier = TeamsNotifier(make_config(teams_webhook_url=TEAMS_URL))
        alert = make_alert()
        with patch("requests.post", return_value=ok_response()) as post:
            assert notifier.send(alert) is True
        post.assert_called_once()
        args, kwargs = post.call_args
        assert args[0] == TEAMS_URL
        assert kwargs["timeout"] == 10
        assert kwargs["json"] == notifier.build_payload(alert)
        assert kwargs["json"]["sections"][0]["facts"][1]["value"] == alert.domain

    def test_send_failure_returns_false(self):
        notifier = TeamsNotifier(make_config(teams_webhook_url=TEAMS_URL))
        bad = ok_response()
        bad.raise_for_status.side_effect = requests.HTTPError("400 Bad Request")
        with patch("requests.post", return_value=bad):
            assert notifier.send(make_alert()) is False
        with patch("requests.post", side_effect=requests.ConnectionError("down")):
            assert notifier.send(make_alert()) is False

    def test_send_unconfigured_returns_false_without_network(self):
        notifier = TeamsNotifier(make_config(teams_webhook_url=""))
        with patch("requests.post") as post:
            assert notifier.send(make_alert()) is False
        post.assert_not_called()
        # Older configs without the attribute at all must not crash.
        legacy = SimpleNamespace()
        assert TeamsNotifier(legacy).send(make_alert()) is False


# --------------------------------------------------------------------------- syslog / CEF


class TestSyslogNotifier:
    def make_notifier(self, **overrides) -> SyslogNotifier:
        return SyslogNotifier(make_config(syslog_enabled=True, **overrides))

    def test_cef_header_and_extension_escaping(self):
        alert = make_alert(
            title="Phish | detected \\ now",
            alert_type="type|x",
            domain="evil=example.com",
            message="line1\nline2 a=b \\ c",
            details={"k": "v=1"},
        )
        cef = self.make_notifier().build_cef(alert)
        header, _, extension = cef.partition("|dhost=")
        assert header.startswith(f"CEF:0|BrandSentra|BrandSentra|{__version__}|")
        assert "|type\\|x|" in header
        assert "|Phish \\| detected \\\\ now|8" in header
        assert extension.startswith("evil\\=example.com cat=high rt=")
        assert "msg=line1\\nline2 a\\=b \\\\ c" in extension
        assert "\n" not in cef
        assert "cs1Label=alertType cs1=type|x" in extension
        assert 'cs2Label=details cs2={"k":"v\\=1"}' in extension
        expected_ms = int(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp() * 1000)
        assert f"rt={expected_ms} " in extension

    @pytest.mark.parametrize(
        "severity,cef",
        [("critical", 10), ("high", 8), ("medium", 5), ("low", 3), ("info", 1), ("x", 1)],
    )
    def test_cef_severity_mapping(self, severity, cef):
        cef_line = self.make_notifier().build_cef(make_alert(severity=severity))
        header_fields = cef_line.split("|", 7)
        assert header_fields[6] == str(cef)

    @pytest.mark.parametrize(
        "facility,severity,pri",
        [
            (16, "critical", 130),
            (16, "high", 131),
            (16, "medium", 132),
            (16, "low", 134),
            (16, "unknown", 133),
            (1, "critical", 10),
        ],
    )
    def test_syslog_pri_computation(self, facility, severity, pri):
        notifier = self.make_notifier(syslog_facility=facility)
        message = notifier.build_syslog_message(make_alert(severity=severity))
        assert message.startswith(f"<{pri}>")

    def test_syslog_message_rfc3164_envelope(self):
        message = self.make_notifier().build_syslog_message(make_alert())
        pattern = (
            r"^<\d{1,3}>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} "
            + re.escape(socket.gethostname())
            + r" brandsentra: CEF:0\|BrandSentra\|"
        )
        assert re.match(pattern, message), message

    def test_udp_send_uses_sendto(self):
        notifier = self.make_notifier(syslog_host="10.0.0.5", syslog_port=1514)
        with patch("socket.socket") as socket_cls:
            sock = socket_cls.return_value
            assert notifier.send(make_alert()) is True
        socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto.assert_called_once()
        data, address = sock.sendto.call_args[0]
        assert address == ("10.0.0.5", 1514)
        assert data.decode("utf-8").startswith("<131>")
        assert "CEF:0|BrandSentra|" in data.decode("utf-8")
        sock.sendall.assert_not_called()
        sock.close.assert_called_once()

    def test_tcp_send_connects_and_uses_sendall(self):
        notifier = self.make_notifier(syslog_host="siem.local", syslog_protocol="TCP")
        with patch("socket.socket") as socket_cls:
            sock = socket_cls.return_value
            assert notifier.send(make_alert()) is True
        socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout.assert_called_once_with(5)
        sock.connect.assert_called_once_with(("siem.local", 514))
        sock.sendall.assert_called_once()
        data = sock.sendall.call_args[0][0]
        assert data.endswith(b"\n")
        assert b"brandsentra: CEF:0|" in data
        sock.sendto.assert_not_called()
        sock.close.assert_called_once()

    def test_send_failure_returns_false_and_closes_socket(self):
        notifier = self.make_notifier()
        with patch("socket.socket") as socket_cls:
            socket_cls.return_value.sendto.side_effect = OSError("network unreachable")
            assert notifier.send(make_alert()) is False
        socket_cls.return_value.close.assert_called_once()

        tcp = self.make_notifier(syslog_protocol="tcp")
        with patch("socket.socket") as socket_cls:
            socket_cls.return_value.connect.side_effect = socket.timeout("timed out")
            assert tcp.send(make_alert()) is False

    def test_disabled_or_unconfigured_returns_false(self):
        with patch("socket.socket") as socket_cls:
            assert SyslogNotifier(make_config(syslog_enabled=False)).send(make_alert()) is False
            assert self.make_notifier(syslog_host="").send(make_alert()) is False
            assert self.make_notifier(syslog_port=0).send(make_alert()) is False
        socket_cls.assert_not_called()


# --------------------------------------------------------------------------- existing notifiers


class TestHttpNotifiers:
    def test_slack_send_posts_blocks(self):
        notifier = SlackNotifier(make_config(slack_webhook_url=SLACK_URL, slack_channel="#soc"))
        alert = make_alert()
        with patch("requests.post", return_value=ok_response()) as post:
            assert notifier.send(alert) is True
        args, kwargs = post.call_args
        assert args[0] == SLACK_URL
        assert kwargs["timeout"] == 10
        body = kwargs["json"]
        assert body["channel"] == "#soc"
        assert body["username"] == "BrandSentra"
        assert alert.title in body["blocks"][0]["text"]["text"]
        assert body["blocks"][2]["text"]["text"] == alert.message

        bad = ok_response()
        bad.raise_for_status.side_effect = requests.HTTPError("500")
        with patch("requests.post", return_value=bad):
            assert notifier.send(alert) is False
        assert SlackNotifier(make_config()).send(alert) is False

    def test_telegram_send_uses_bot_api(self):
        notifier = TelegramNotifier(
            make_config(telegram_bot_token="123:ABC", telegram_chat_id="-100987")
        )
        alert = make_alert()
        with patch("requests.post", return_value=ok_response()) as post:
            assert notifier.send(alert) is True
        args, kwargs = post.call_args
        assert args[0] == "https://api.telegram.org/bot123:ABC/sendMessage"
        assert kwargs["json"]["chat_id"] == "-100987"
        assert kwargs["json"]["parse_mode"] == "Markdown"
        assert alert.title in kwargs["json"]["text"]
        assert alert.domain in kwargs["json"]["text"]

        with patch("requests.post", side_effect=requests.Timeout("slow")):
            assert notifier.send(alert) is False
        assert TelegramNotifier(make_config(telegram_bot_token="x")).send(alert) is False

    def test_webhook_send_signs_payload(self):
        secret = "s3cr3t"
        notifier = WebhookNotifier(make_config(webhook_url=WEBHOOK_URL, webhook_secret=secret))
        alert = make_alert()
        with patch("requests.post", return_value=ok_response()) as post:
            assert notifier.send(alert) is True
        args, kwargs = post.call_args
        assert args[0] == WEBHOOK_URL
        assert kwargs["timeout"] == 10
        assert kwargs["headers"]["Content-Type"] == "application/json"
        payload = kwargs["data"]
        assert json.loads(payload) == alert.to_dict()
        expected = hmac.new(secret.encode(), payload.encode(), "sha256").hexdigest()
        assert kwargs["headers"]["X-KCW-Signature"] == expected

        unsigned = WebhookNotifier(make_config(webhook_url=WEBHOOK_URL, webhook_secret=""))
        with patch("requests.post", return_value=ok_response()) as post:
            assert unsigned.send(alert) is True
        assert "X-KCW-Signature" not in post.call_args[1]["headers"]

        with patch("requests.post", side_effect=requests.ConnectionError("refused")):
            assert notifier.send(alert) is False

    def test_email_unconfigured_returns_false(self):
        notifier = EmailNotifier(make_config(email_smtp_server=""))
        with patch("smtplib.SMTP") as smtp:
            assert notifier.send(make_alert()) is False
        smtp.assert_not_called()


# --------------------------------------------------------------------------- dispatcher


class TestNotificationDispatcher:
    def make_dispatcher(self, clock=None, **overrides):
        config = make_config(**overrides)
        throttle = AlertThrottle(config.cooldown_seconds, now=clock) if clock else None
        dispatcher = NotificationDispatcher(config, throttle=throttle)
        fake = FakeNotifier()
        dispatcher.notifiers = [("fake", fake)]
        dispatcher.stats["per_channel"] = {"fake": {"sent": 0, "failed": 0}}
        return dispatcher, fake

    def test_no_channels_enabled_returns_empty(self):
        dispatcher = NotificationDispatcher(make_config())
        assert dispatcher.notifiers == []
        assert dispatcher.channels == []
        assert dispatcher.dispatch(make_alert(severity="critical")) == {}
        assert dispatcher.stats["dispatched"] == 1
        assert dispatcher.stats["sent"] == 0
        assert dispatcher.stats["per_channel"] == {}

    def test_channels_list_follows_config(self):
        config = make_config(
            slack_enabled=True,
            slack_webhook_url=SLACK_URL,
            webhook_enabled=True,
            webhook_url=WEBHOOK_URL,
            teams_enabled=True,
            teams_webhook_url=TEAMS_URL,
            syslog_enabled=True,
        )
        dispatcher = NotificationDispatcher(config)
        assert dispatcher.channels == ["slack", "webhook", "teams", "syslog"]
        assert set(dispatcher.stats["per_channel"]) == {"slack", "webhook", "teams", "syslog"}
        assert isinstance(dict(dispatcher.notifiers)["teams"], TeamsNotifier)
        assert isinstance(dict(dispatcher.notifiers)["syslog"], SyslogNotifier)
        assert dispatcher.min_severity == "medium"
        assert dispatcher.throttle.cooldown_seconds == 3600

    def test_legacy_config_without_new_attributes(self):
        legacy = SimpleNamespace(
            email_enabled=False, slack_enabled=False, telegram_enabled=False, webhook_enabled=False
        )
        dispatcher = NotificationDispatcher(legacy)
        assert dispatcher.channels == []
        assert dispatcher.min_severity == "medium"
        assert dispatcher.throttle.cooldown_seconds == 3600

    def test_min_severity_suppression(self):
        dispatcher, fake = self.make_dispatcher(min_severity="high")
        assert dispatcher.dispatch(make_alert(severity="medium")) == {}
        assert dispatcher.dispatch(make_alert(severity="low")) == {}
        assert dispatcher.stats["suppressed_severity"] == 2
        assert fake.alerts == []
        assert dispatcher.dispatch(make_alert(severity="high")) == {"fake": True}
        assert dispatcher.dispatch(make_alert(severity="critical", domain="other.com")) == {
            "fake": True
        }
        assert len(fake.alerts) == 2

    def test_duplicate_suppression_and_cooldown_expiry(self):
        clock = FakeClock()
        dispatcher, fake = self.make_dispatcher(clock=clock, cooldown_seconds=600)
        assert dispatcher.dispatch(make_alert()) == {"fake": True}
        assert dispatcher.dispatch(make_alert()) == {}
        assert dispatcher.stats["suppressed_duplicate"] == 1
        assert dispatcher.throttle.suppressed == 1
        clock.advance(600)
        assert dispatcher.dispatch(make_alert()) == {"fake": True}
        assert len(fake.alerts) == 2

    def test_force_bypasses_severity_and_throttle(self):
        dispatcher, fake = self.make_dispatcher(min_severity="critical", cooldown_seconds=3600)
        assert dispatcher.dispatch(make_alert(severity="low")) == {}
        assert dispatcher.dispatch(make_alert(severity="low"), force=True) == {"fake": True}
        assert dispatcher.dispatch(make_alert(severity="low"), force=True) == {"fake": True}
        assert dispatcher.stats["suppressed_severity"] == 1
        assert dispatcher.stats["suppressed_duplicate"] == 0
        assert len(fake.alerts) == 2

    def test_dispatch_critical_sets_severity_and_forces(self):
        dispatcher, fake = self.make_dispatcher(min_severity="critical")
        alert = make_alert(severity="low")
        dispatcher.dispatch(alert)  # recorded nothing (suppressed by severity)
        assert dispatcher.dispatch_critical(alert) == {"fake": True}
        assert alert.severity == "critical"
        assert fake.alerts == [alert]

    def test_stats_counters_per_channel(self):
        dispatcher, fake = self.make_dispatcher()
        failing = FakeNotifier(result=False)
        dispatcher.notifiers.append(("broken", failing))
        dispatcher.stats["per_channel"]["broken"] = {"sent": 0, "failed": 0}

        assert dispatcher.dispatch(make_alert()) == {"fake": True, "broken": False}
        assert dispatcher.dispatch(make_alert(domain="second.com")) == {
            "fake": True,
            "broken": False,
        }
        dispatcher.dispatch(make_alert())  # duplicate
        dispatcher.dispatch(make_alert(severity="low", domain="third.com"))  # below medium

        assert dispatcher.stats["dispatched"] == 2
        assert dispatcher.stats["sent"] == 2
        assert dispatcher.stats["failed"] == 2
        assert dispatcher.stats["suppressed_duplicate"] == 1
        assert dispatcher.stats["suppressed_severity"] == 1
        assert dispatcher.stats["per_channel"] == {
            "fake": {"sent": 2, "failed": 0},
            "broken": {"sent": 0, "failed": 2},
        }

    def test_notifier_exception_counts_as_failure(self):
        dispatcher, _ = self.make_dispatcher()
        exploding = MagicMock()
        exploding.send.side_effect = RuntimeError("boom")
        dispatcher.notifiers.append(("boom", exploding))
        assert dispatcher.dispatch(make_alert()) == {"fake": True, "boom": False}
        assert dispatcher.stats["per_channel"]["boom"] == {"sent": 0, "failed": 1}

    def test_custom_empty_throttle_is_kept(self):
        throttle = AlertThrottle(cooldown_seconds=5, now=FakeClock())
        dispatcher = NotificationDispatcher(make_config(), throttle=throttle)
        assert dispatcher.throttle is throttle

    def test_test_channels_sends_forced_low_severity_alert(self):
        dispatcher, fake = self.make_dispatcher(min_severity="critical")
        assert dispatcher.test_channels() == {"fake": True}
        assert dispatcher.test_channels() == {"fake": True}  # not throttled
        assert len(fake.alerts) == 2
        alert = fake.alerts[0]
        assert alert.severity == "low"
        assert alert.alert_type == "test"
        assert "BrandSentra" in alert.title
        assert dispatcher.stats["suppressed_severity"] == 0
        assert dispatcher.stats["suppressed_duplicate"] == 0

    def test_end_to_end_teams_and_webhook_channels(self):
        config = make_config(
            teams_enabled=True,
            teams_webhook_url=TEAMS_URL,
            webhook_enabled=True,
            webhook_url=WEBHOOK_URL,
            webhook_secret="k",
            min_severity="low",
        )
        dispatcher = NotificationDispatcher(config)
        with patch("requests.post", return_value=ok_response()) as post:
            results = dispatcher.dispatch(make_alert())
        assert results == {"webhook": True, "teams": True}
        urls = [call.args[0] for call in post.call_args_list]
        assert urls == [WEBHOOK_URL, TEAMS_URL]
        assert dispatcher.stats["sent"] == 2
