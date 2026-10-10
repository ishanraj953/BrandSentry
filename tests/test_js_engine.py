#!/usr/bin/env python3
"""
Parity tests between the Python engine and its browser port (demo/engine.js).

Requires Node.js; the comparison tests are skipped when ``node`` is missing.
"""

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.config.settings import DomainAnalysisConfig
from src.core.brand_monitor import BrandMonitor
from src.core.domain_analyzer import DomainAnalyzer
from src.core.phishing_detector import PhishingDetector

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

CORPUS = [
    # scoring rules fixed in 2.5.0: hosting scored once, leading www ignored
    "verify-account-portal.pages.dev",
    "www.portal.secure-update.xyz",
    # legitimate
    "nbk.com",
    "login.nbk.com",
    "www.nbk.com.kw",
    "kfh.com",
    "e.gov.kw",
    "kw.zain.com",
    "google.com",
    "paypal.com",
    "github.com",
    "bbc.co.uk",
    "_news.com",
    # traps
    "kibana.io",
    "mohammed.com",
    "pacific.com",
    "moisture.com",
    "stcoupon.com",
    "zainab.com",
    "knetwork.com",
    "nbc.com",
    "abc.com",
    "mom.com",
    "_.com",
    "_-jobs.com",
    "q8car.com",
    "steampowered.com",
    "purchase.com",
    # squats
    "nbk.xyz",
    "nbkk.com",
    "nkb.com",
    "nbk-login.com",
    "nbklogin.com",
    "nbk0nline.com",
    "nbк.com",
    "xn--nb-3lc.com",
    "nbk.com.verify-login.tk",
    "nbk.evil.com",
    "login-nbk-kw.top",
    "kfh-online.xyz",
    "_-finance-house.com",
    "baitak-update.com",
    "knetpay.info",
    "knet-secure.xyz",
    "k-net.com",
    "kpay-kw.com",
    "moilogin.com",
    "moi-kw.com",
    "moi-fines.top",
    "moi-gov-kw.com",
    "paci-civilid.com",
    "sahel-app.com",
    "egov-kw.com",
    "bourgan.com",
    "burganbank.com",
    "gulfbank-login.com",
    "boubyan-verify.com",
    "warbabank.xyz",
    "zain-kw.com",
    "zainpay.com",
    "ooredoo-kw.top",
    "stc-kw.com",
    "stckw.com",
    "vivakw.com",
    "_airways-booking.com",
    "talabat-offers.com",
    "cbk-secure.com",
    "tijari-online.com",
    "xn----zmcb6dvcikfqw.com",
    "بيتك-تحديث.com",
    "nbk-secure-login.web.app",
    "nbk.com-secure.icu",
    "secure-nbk-com.ga",
    "nationalbankof_.com",
    "wwwnbk.com",
    "nbkbank.com",
    "kfhh.com",
    "kfhbank.com",
    "nbk2024.com",
    "nbc-_-login.top",
    "cbk-nbk-login.com",
    "abk-login.tk",
    "kib-secure.com",
    "nbk-xyzzy.com",
    "paypal-account-verify.com",
    "secure-update.ga",
    "x9q2z8k1m3w7v5p4.com",
    "a.b.c.d.this-is-a-very-long-suspicious-domain-name-targeting-_123456.xyz",
    "http://192.168.1.10/login",
    "https://NBK-Login.xyz/verify",
    "*.nbk-verify.top",
    "bank.com",
    "_-bank.tk",
]

NODE_HARNESS = r"""
const path = require("path");
require(path.join(process.argv[1], "demo", "engine-data.js"));
const KCW = require(path.join(process.argv[1], "demo", "engine.js"));
const corpus = JSON.parse(require("fs").readFileSync(0, "utf8"));
const detector = new KCW.PhishingDetector();
const analyzer = new KCW.DomainAnalyzer({ legitimateDomains: new KCW.BrandMonitor().protectedDomains() });
const monitor = new KCW.BrandMonitor({ dedupeWindowSeconds: 0 });
const out = {};
for (const d of corpus) {
  const v = detector.analyze(d);
  const parsed = KCW.parseDomain(d);
  out[d] = {
    parsed: { hostname: parsed.hostname, registrable: parsed.registrable, label: parsed.label, suffix: parsed.suffix,
              unicode_label: parsed.unicode_label, is_idn: parsed.is_idn, hosting_platform: parsed.hosting_platform, valid: parsed.valid },
    risk_score: v.risk_score, risk_level: v.risk_level, is_phishing: v.is_phishing,
    categories: v.categories, matched_brands: v.matched_brands,
    indicator_types: v.indicators.map((i) => i.type).sort(),
    analyzer: analyzer.analyze(d).map((r) => [r.target, r.attack_types.slice().sort(), r.risk_level]),
    monitor: monitor.checkDomain(d, "scan", false).map((a) => [a.brand_name, a.alert_type, a.severity]).sort(),
  };
}
process.stdout.write(JSON.stringify(out));
"""


def run_js(corpus):
    proc = subprocess.run(
        [NODE, "-e", NODE_HARNESS, str(ROOT)],
        input=json.dumps(corpus),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        cwd=str(ROOT),
    )
    return json.loads(proc.stdout)


def python_results(corpus):
    from src.utils.domain import parse_domain

    detector = PhishingDetector()
    monitor = BrandMonitor(dedupe_window_seconds=0)
    analyzer = DomainAnalyzer(
        DomainAnalysisConfig(), legitimate_domains=monitor.protected_domains()
    )
    out = {}
    for d in corpus:
        v = detector.analyze(d)
        p = parse_domain(d)
        out[d] = {
            "parsed": {
                "hostname": p.hostname,
                "registrable": p.registrable,
                "label": p.label,
                "suffix": p.suffix,
                "unicode_label": p.unicode_label,
                "is_idn": p.is_idn,
                "hosting_platform": p.hosting_platform,
                "valid": p.valid,
            },
            "risk_score": v.risk_score,
            "risk_level": v.risk_level,
            "is_phishing": v.is_phishing,
            "categories": v.categories,
            "matched_brands": v.matched_brands,
            "indicator_types": sorted(i["type"] for i in v.indicators),
            "analyzer": [
                [r.target_domain, sorted(r.attack_types), r.risk_level] for r in analyzer.analyze(d)
            ],
            "monitor": sorted(
                [a.brand_name, a.alert_type, a.severity]
                for a in monitor.check_domain(d, record=False)
            ),
        }
    return out


def test_engine_data_is_current():
    """demo/engine-data.js must be regenerated whenever the Python tables change."""
    proc = subprocess.run(
        [sys.executable, "scripts/export_engine_data.py", "--check"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(NODE is None, reason="node is not installed")
class TestParity:
    @pytest.fixture(scope="class")
    def results(self):
        return python_results(CORPUS), run_js(CORPUS)

    def test_parsing(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["parsed"], js[d]["parsed"])
            for d in CORPUS
            if py[d]["parsed"] != js[d]["parsed"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_phishing_verdicts(self, results):
        py, js = results
        keys = (
            "risk_score",
            "risk_level",
            "is_phishing",
            "categories",
            "matched_brands",
            "indicator_types",
        )
        mismatches = {}
        for d in CORPUS:
            diff = {k: (py[d][k], js[d][k]) for k in keys if py[d][k] != js[d][k]}
            if diff:
                mismatches[d] = diff
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_analyzer(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["analyzer"], js[d]["analyzer"])
            for d in CORPUS
            if py[d]["analyzer"] != js[d]["analyzer"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_brand_monitor(self, results):
        py, js = results
        mismatches = {
            d: (py[d]["monitor"], js[d]["monitor"])
            for d in CORPUS
            if py[d]["monitor"] != js[d]["monitor"]
        }
        assert not mismatches, json.dumps(mismatches, ensure_ascii=False, indent=1)

    def test_permutations_match(self):
        analyzer = DomainAnalyzer(DomainAnalysisConfig())
        py = analyzer.generate_permutations_detailed(
            "nbk.com", tlds=["com", "kw", "com.kw"], max_results=400
        )
        script = (
            'const path=require("path");require(path.join(process.argv[1],"demo","engine-data.js"));'
            'const KCW=require(path.join(process.argv[1],"demo","engine.js"));'
            "const a=new KCW.DomainAnalyzer();"
            'process.stdout.write(JSON.stringify(a.generatePermutationsDetailed("nbk.com",{tlds:["com","kw","com.kw"],maxResults:400})));'
        )
        js = json.loads(
            subprocess.run(
                [NODE, "-e", script, str(ROOT)], capture_output=True, text=True, check=True
            ).stdout
        )
        assert [(p["domain"], p["technique"]) for p in py] == [
            (p["domain"], p["technique"]) for p in js
        ]


X509_HARNESS = r"""
globalThis.window = globalThis; window.KCW_APP = { esc: (s) => s, setText() {}, db: {}, settings: {}, engine() {}, saveSetting() {} };
window.addEventListener = () => {}; globalThis.document = { getElementById: () => null };
const path = require("path");
require(path.join(process.argv[1], "demo", "engine-data.js"));
require(path.join(process.argv[1], "demo", "engine.js"));
require(path.join(process.argv[1], "demo", "discovery.js"));
const leaves = JSON.parse(require("fs").readFileSync(0, "utf8"));
const pick = (p) => ({ all_domains: p.all_domains, issuer: p.issuer, entry_type: p.entry_type, not_before: p.not_before, serial: p.serial_number });
const out = leaves.map((item) => { try { if (item.tile) { const u8 = Uint8Array.from(Buffer.from(item.tile, "base64")); return { tile: window.KCW_X509.parseDataTile(u8).map(pick), path: window.KCW_X509.tilePath(item.index) }; } return pick(window.KCW_X509.parseLeafInput(item)); } catch (e) { return { error: e.message }; } });
process.stdout.write(JSON.stringify(out), () => process.exit(0));
"""


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_browser_x509_parser_matches_python():
    """demo/discovery.js must extract the same certificate fields as src/utils/x509.py."""
    from src.utils import x509
    from tests.test_ct_tailer import certificate, leaf_input, tbs

    leaves = [
        leaf_input(
            certificate("login.nbk-secure.xyz", ["login.nbk-secure.xyz", "www.nbk-secure.xyz"]), 0
        ),
        leaf_input(tbs("kfh-verify.top", ["kfh-verify.top"], poison=True), 1),
        leaf_input(
            certificate("host._-example.com", [f"h{i}._-example.com" for i in range(40)]),
            0,
        ),
        leaf_input(
            certificate("xn--mgbaa0aog6m.com", ["xn--mgbaa0aog6m.com"], issuer_org="ZeroSSL"), 0
        ),
    ]
    from tests.test_ct_tailer import tile_leaf

    tile = tile_leaf(certificate("a._-example.com", ["a._-example.com"]), 0) + tile_leaf(
        tbs("b._-example.com", ["b._-example.com"], poison=True), 1
    )
    payload = leaves + [{"tile": base64.b64encode(tile).decode(), "index": 1234567}]
    js = json.loads(
        subprocess.run(
            [NODE, "-e", X509_HARNESS, str(ROOT)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
            cwd=str(ROOT),
        ).stdout
    )
    tile_js = js.pop()
    assert tile_js["path"] == x509.tile_path(1234567) == "x001/x234/567"
    assert [t["all_domains"] for t in tile_js["tile"]] == [
        p["all_domains"] for p in x509.parse_data_tile(tile)
    ]
    assert [t["entry_type"] for t in tile_js["tile"]] == ["x509", "precert"]
    for b64, got in zip(leaves, js):
        want = x509.parse_leaf_input(b64)
        assert got == {
            "all_domains": want["all_domains"],
            "issuer": want["issuer"],
            "entry_type": want["entry_type"],
            "not_before": want["not_before"].replace("+00:00", ".000Z"),
            "serial": want["serial_number"],
        }
