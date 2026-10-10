#!/usr/bin/env python3
"""Tests for the command line interface (main.py)."""

import json

import pytest

import main as cli
import src.core.squat_watcher as squat_module


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KCW_CONFIG", raising=False)
    (tmp_path / "config.yaml").write_text(
        "database:\n  db_path: data/test.db\nsquat_watcher:\n  tlds: [com]\n"
        "notifications:\n  min_severity: low\n"
    )
    return tmp_path


def run(argv, capsys):
    code = cli.main(["--no-banner", *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_version_and_help(capsys):
    assert run(["version"], capsys)[0] == 0
    code, out, _ = run([], capsys)
    assert code == 0 and "usage" in out.lower()


def test_scan_json_and_text(workdir, capsys):
    code, out, _ = run(["scan", "https://NBK-login.xyz/verify", "--json", "--no-persist"], capsys)
    assert code == 0
    data = json.loads(out)
    assert data["domain"] == "nbk-login.xyz"
    assert data["phishing"]["is_phishing"] is True
    assert data["brand_alerts"]
    code, out, _ = run(["scan", "nbk-login.xyz", "--fail-on-phishing"], capsys)
    assert code == 1
    assert "Brand Alerts" in out and "Recommendation" in out
    assert run(["scan", "   "], capsys)[0] == 2


def test_scan_persists_and_report(workdir, capsys):
    run(["scan", "nbk-login.xyz"], capsys)
    code, out, _ = run(["report", "--days", "2", "--json"], capsys)
    assert code == 0
    summary = json.loads(out)
    assert summary["totals"]["total_domains"] == 1
    assert summary["alerts"]["total"] == 1
    out_file = workdir / "report.md"
    code, out, _ = run(["report", "--out", str(out_file)], capsys)
    assert code == 0 and out_file.read_text().startswith("# BrandSentra Report")


def test_bulk_json_csv_and_table(workdir, capsys):
    listing = workdir / "domains.txt"
    listing.write_text("# comment\nnbk-login.xyz\ngoogle.com\n\n   \n")
    code, out, _ = run(["bulk", str(listing), "--json", "--no-persist"], capsys)
    data = json.loads(out)
    assert code == 0 and data["total"] == 2 and data["results"][0]["domain"] == "nbk-login.xyz"
    csv_out = workdir / "out.csv"
    assert run(["bulk", str(listing), "--csv", str(csv_out), "--no-persist"], capsys)[0] == 0
    assert csv_out.read_text().splitlines()[0].startswith("domain,risk_score")
    code, out, _ = run(["bulk", str(listing), "--no-persist"], capsys)
    assert code == 0 and "1 flagged as phishing" in out
    empty = workdir / "empty.txt"
    empty.write_text("")
    assert run(["bulk", str(empty)], capsys)[0] == 2


def test_permutations(workdir, capsys, monkeypatch):
    code, out, _ = run(
        ["permutations", "nbk.com", "--tlds", "com", "kw", "--limit", "30", "--json"], capsys
    )
    data = json.loads(out)
    assert code == 0 and data["total"] == 30 and data["permutations"][0]["technique"] == "tld_swap"
    monkeypatch.setattr(
        squat_module,
        "make_resolver",
        lambda timeout=3.0: (lambda d: ["1.1.1.1"] if d == "nbkk.com" else []),
    )
    code, out, _ = run(
        ["permutations", "nbk.com", "--resolve", "--live-only", "--limit", "200"], capsys
    )
    assert code == 0 and "nbkk.com" in out and "1.1.1.1" in out


def test_watch_squats_once(workdir, capsys, monkeypatch):
    monkeypatch.setattr(
        squat_module,
        "make_resolver",
        lambda timeout=3.0: (lambda d: ["2.2.2.2"] if d == "nbkk.com" else []),
    )
    code, out, _ = run(
        ["watch-squats", "--once", "--brand", "nbk.com", "--json", "--no-notify"], capsys
    )
    data = json.loads(out)
    assert code == 0 and data["live"] == 1 and data["new"] == 1
    assert data["sightings"][0]["domain"] == "nbkk.com"
    code, out, _ = run(["watch-squats", "--once", "--brand", "nbk.com", "--no-notify"], capsys)
    assert code == 0 and "1 live, 0 new" in out


def test_allowlist_flow(workdir, capsys):
    code, out, _ = run(["allowlist", "list"], capsys)
    assert code == 0 and "empty" in out
    assert run(["allowlist", "add", "nbk-login.xyz", "--reason", "ours"], capsys)[1].startswith(
        "Added"
    )
    assert run(["allowlist", "add", "nbk-login.xyz"], capsys)[1].startswith("Already")
    code, out, _ = run(["allowlist", "list", "--json"], capsys)
    assert json.loads(out)[0]["domain"] == "nbk-login.xyz"
    code, out, _ = run(["scan", "nbk-login.xyz", "--json", "--no-persist"], capsys)
    assert json.loads(out)["allowlisted"] is True
    assert run(["allowlist", "remove", "nbk-login.xyz"], capsys)[0] == 0
    assert run(["allowlist", "remove", "nbk-login.xyz"], capsys)[0] == 1
    with pytest.raises(SystemExit):
        cli.main(["allowlist", "add"])


def test_export_stix(workdir, capsys):
    run(["scan", "nbk-login.xyz"], capsys)
    out_file = workdir / "bundle.json"
    code, out, _ = run(["export-stix", "--out", str(out_file), "--tlp", "green"], capsys)
    assert code == 0 and "1 indicators" in out
    bundle = json.loads(out_file.read_text())
    assert bundle["type"] == "bundle"
    code, out, _ = run(["export-stix", "--min-risk", "10"], capsys)
    assert json.loads(out)["type"] == "bundle"


def test_config_command(workdir, capsys):
    code, out, _ = run(["config", "--json"], capsys)
    data = json.loads(out)
    assert code == 0 and data["config"]["database"]["db_path"] == "data/test.db"
    assert any("secret_key" in w for w in data["warnings"])
    assert run(["config", "--check"], capsys)[0] == 1


def test_test_notify_without_channels(workdir, capsys):
    code, out, _ = run(["test-notify"], capsys)
    assert code == 1 and "No notification channels" in out


def test_monitor_replay(workdir, capsys):
    capture = workdir / "certs.jsonl"
    messages = [
        {
            "message_type": "certificate_update",
            "data": {
                "source": {"name": "test"},
                "leaf_cert": {
                    "all_domains": ["novapay-secure-login.tk", "*.novapay-secure-login.tk"],
                    "issuer": {"O": "Let's Encrypt"},
                },
            },
        },
        {"leaf_cert": {"all_domains": ["kestrel-verify.top"], "issuer": {"O": "ZeroSSL"}}},
        {"message_type": "heartbeat"},
    ]
    capture.write_text("\n".join(json.dumps(m) for m in messages) + "\nnot json\n")
    code, out, _ = run(["monitor", "--replay", str(capture), "--no-notify"], capsys)
    assert code == 0
    assert "Replayed 3 messages" in out
    assert "2 matching certificates" in out
    assert "2 alerts in database" in out
