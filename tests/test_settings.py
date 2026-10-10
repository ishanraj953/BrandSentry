#!/usr/bin/env python3
"""Tests for src/config/settings.py."""

import textwrap

from src.config.settings import (
    Settings,
    apply_dict,
    apply_env_overrides,
    find_config_path,
    load_config,
    to_dict,
    validate,
)


def test_defaults_without_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KCW_CONFIG", raising=False)
    settings = load_config()
    assert settings.api.port == 5000
    assert settings.config_path is None
    assert "novapay.com" in settings.domain_analysis.protected_brands
    assert settings.notifications.min_severity == "medium"
    assert settings.threat_intel.urlhaus_enabled is True


def test_loads_every_section(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent("""
            certstream:
              keywords: [a, b]
              retry_delay: "7"
            domain_analysis:
              protected_brands: [example.com]
              allowlist: [good.example]
              levenshtein_threshold: 2
            database:
              db_path: /tmp/x.db
            api:
              port: 8080
              auth_required: "yes"
            notifications:
              slack_enabled: true
              min_severity: high
            threat_intel:
              cache_ttl_seconds: 5
            squat_watcher:
              tlds: [com, kw]
              interval_seconds: 600
            brands:
              - name: Test Bank
                domains: [testbank.com]
                keywords: [testbank]
            log_level: debug
            data_dir: /var/kcw
            unknown_key: 1
            """))
    settings = load_config(str(cfg))
    assert settings.certstream.keywords == ["a", "b"]
    assert settings.certstream.retry_delay == 7
    assert settings.domain_analysis.protected_brands == ["example.com"]
    assert settings.domain_analysis.allowlist == ["good.example"]
    assert settings.database.db_path == "/tmp/x.db"
    assert settings.api.port == 8080
    assert settings.api.auth_required is True
    assert settings.notifications.slack_enabled is True
    assert settings.notifications.min_severity == "high"
    assert settings.threat_intel.cache_ttl_seconds == 5
    assert settings.squat_watcher.tlds == ["com", "kw"]
    assert settings.brands[0]["name"] == "Test Bank"
    assert settings.log_level == "DEBUG"
    assert settings.data_dir == "/var/kcw"
    assert settings.config_path == str(cfg)


def test_local_config_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KCW_CONFIG", raising=False)
    (tmp_path / "config.yaml").write_text("api:\n  port: 1\n")
    (tmp_path / "config.local.yaml").write_text("api:\n  port: 2\n")
    assert find_config_path() == "config.local.yaml"
    assert load_config().api.port == 2


def test_kcw_config_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    special = tmp_path / "special.yaml"
    special.write_text("api:\n  port: 3\n")
    monkeypatch.setenv("KCW_CONFIG", str(special))
    assert load_config().api.port == 3


def test_missing_explicit_path_falls_back_to_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KCW_CONFIG", raising=False)
    settings = load_config(str(tmp_path / "nope.yaml"))
    assert settings.api.port == 5000


def test_env_overrides_with_coercion():
    settings = Settings()
    env = {
        "KCW_API_PORT": "9000",
        "KCW_AUTH_REQUIRED": "true",
        "KCW_VT_API_KEY": "vt-key",
        "KCW_ADMIN_PASSWORD": "s3cret",
        "KCW_LOG_LEVEL": "WARNING",
        "KCW_TEAMS_WEBHOOK": "https://teams.example/hook",
        "KCW_DB_PATH": "/data/x.db",
        "KCW_SLACK_WEBHOOK": "",
    }
    apply_env_overrides(settings, env)
    assert settings.api.port == 9000
    assert settings.api.auth_required is True
    assert settings.threat_intel.virustotal_api_key == "vt-key"
    assert settings.api.admin_password == "s3cret"
    assert settings.log_level == "WARNING"
    assert settings.notifications.teams_webhook_url == "https://teams.example/hook"
    assert settings.database.db_path == "/data/x.db"
    assert settings.notifications.slack_webhook_url == ""


def test_invalid_values_are_ignored_not_fatal():
    settings = Settings()
    apply_dict(settings, {"api": {"port": "not-a-number", "debug": "maybe"}})
    assert settings.api.port == 5000
    assert settings.api.debug is False


def test_list_from_comma_string():
    settings = Settings()
    apply_dict(settings, {"certstream": {"keywords": "nbk, kfh ,cbk"}})
    assert settings.certstream.keywords == ["nbk", "kfh", "cbk"]


def test_validate_warns_on_defaults():
    warnings = validate(Settings())
    joined = " ".join(warnings)
    assert "secret_key" in joined
    assert "admin_password" in joined


def test_validate_channel_misconfiguration():
    settings = Settings()
    settings.notifications.slack_enabled = True
    settings.notifications.min_severity = "urgent"
    warnings = validate(settings)
    assert any("slack" in w for w in warnings)
    assert any("min_severity" in w for w in warnings)


def test_to_dict_redacts_secrets():
    settings = Settings()
    settings.threat_intel.virustotal_api_key = "abc"
    settings.notifications.slack_webhook_url = "https://hooks.slack.com/x"
    data = to_dict(settings)
    assert data["threat_intel"]["virustotal_api_key"] == "***"
    assert data["notifications"]["slack_webhook_url"] == "***"
    assert data["api"]["port"] == 5000
    assert to_dict(settings, redact=False)["threat_intel"]["virustotal_api_key"] == "abc"
