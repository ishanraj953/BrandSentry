#!/usr/bin/env python3
"""
BrandSentra - STIX 2.1 export tests
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import __version__  # noqa: E402
from src.core.stix_export import (  # noqa: E402
    KCW_NAMESPACE,
    TLP_MARKINGS,
    build_stix_bundle,
    bundle_to_json,
    escape_pattern_value,
    make_indicator,
    stix_timestamp,
)

NOW = datetime(2026, 9, 24, 12, 30, 45, 123456, tzinfo=timezone.utc)
STIX_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

SAMPLE_RECORDS = [
    {
        "domain": "NBK-Secure-Login.com",
        "risk_score": 92.4,
        "categories": ["brand_impersonation", "suspicious_keywords"],
        "first_seen": "2026-09-01T08:00:00Z",
        "last_seen": "2026-09-20T09:15:30.250Z",
        "source": "certstream",
        "brand": "National Banking Corporation (NBK)",
        "alert_type": "domain_squat",
        "matched_keywords": ["nbk", "login", "secure"],
    },
    {
        "domain": "kfh-verify.xyz",
        "risk_score": 35,
        "categories": ["high_risk_tld"],
        "source": "scan",
    },
    {
        "domain": "random-shop.io",
        "risk_score": 10,
    },
]


def _objects_by_type(bundle, obj_type):
    return [obj for obj in bundle["objects"] if obj["type"] == obj_type]


def _single_indicator(record, **kwargs):
    return make_indicator(
        record,
        identity_id="identity--00000000-0000-0000-0000-000000000000",
        marking_id=TLP_MARKINGS["amber"],
        now=kwargs.pop("now", NOW),
    )


class TestHelpers:
    """Tests for the small formatting helpers."""

    def test_stix_timestamp_millisecond_precision_and_utc(self):
        assert stix_timestamp(NOW) == "2026-09-24T12:30:45.123Z"
        # Aware non-UTC datetimes are converted to UTC.
        plus_three = datetime(2026, 9, 24, 15, 30, 45, 999999, tzinfo=timezone(timedelta(hours=3)))
        assert stix_timestamp(plus_three) == "2026-09-24T12:30:45.999Z"
        # Naive datetimes are treated as UTC.
        assert stix_timestamp(datetime(2026, 1, 1)) == "2026-01-01T00:00:00.000Z"

    def test_escape_pattern_value(self):
        assert escape_pattern_value("plain.com") == "plain.com"
        assert escape_pattern_value("it's") == "it\\'s"
        assert escape_pattern_value("back\\slash") == "back\\\\slash"
        assert escape_pattern_value("a'b\\c") == "a\\'b\\\\c"


class TestBundleStructure:
    """Tests for the overall bundle layout."""

    def test_bundle_structure_and_object_types(self):
        bundle = build_stix_bundle(SAMPLE_RECORDS, now=NOW)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        uuid.UUID(bundle["id"].split("--", 1)[1])  # valid UUID

        objects = bundle["objects"]
        assert objects[0]["type"] == "identity"
        assert objects[1]["type"] == "marking-definition"
        assert all(obj["type"] == "indicator" for obj in objects[2:])
        assert len(_objects_by_type(bundle, "indicator")) == len(SAMPLE_RECORDS)
        assert all(obj["spec_version"] == "2.1" for obj in objects)

        identity_id = objects[0]["id"]
        marking_id = objects[1]["id"]
        for ind in objects[2:]:
            assert ind["created_by_ref"] == identity_id
            assert ind["object_marking_refs"] == [marking_id]

    def test_identity_object(self):
        bundle = build_stix_bundle(SAMPLE_RECORDS, producer_name="Acme SOC", now=NOW)
        identity = _objects_by_type(bundle, "identity")[0]
        expected_id = "identity--" + str(uuid.uuid5(KCW_NAMESPACE, "identity:Acme SOC"))
        assert identity["id"] == expected_id
        assert identity["name"] == "Acme SOC"
        assert identity["identity_class"] == "organization"
        assert identity["sectors"] == ["technology"]
        assert identity["created"] == identity["modified"] == stix_timestamp(NOW)
        assert "BrandSentra" in identity["description"]
        assert __version__ in identity["description"]

    @pytest.mark.parametrize("colour", ["white", "green", "amber", "red"])
    def test_marking_definition_per_tlp_colour(self, colour):
        bundle = build_stix_bundle(SAMPLE_RECORDS, tlp=colour, now=NOW)
        marking = _objects_by_type(bundle, "marking-definition")[0]
        assert marking == {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": TLP_MARKINGS[colour],
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": f"TLP:{colour.upper()}",
            "definition": {"tlp": colour},
        }
        for ind in _objects_by_type(bundle, "indicator"):
            assert ind["object_marking_refs"] == [TLP_MARKINGS[colour]]

    def test_tlp_case_and_prefix_are_tolerated(self):
        bundle = build_stix_bundle(SAMPLE_RECORDS, tlp="TLP:Red", now=NOW)
        marking = _objects_by_type(bundle, "marking-definition")[0]
        assert marking["id"] == TLP_MARKINGS["red"]

    @pytest.mark.parametrize("bad", ["purple", "", None, "amber+strict"])
    def test_unknown_tlp_raises(self, bad):
        with pytest.raises(ValueError):
            build_stix_bundle(SAMPLE_RECORDS, tlp=bad, now=NOW)

    def test_empty_input_yields_identity_and_marking_only(self):
        bundle = build_stix_bundle([], now=NOW)
        assert [obj["type"] for obj in bundle["objects"]] == ["identity", "marking-definition"]
        assert bundle["id"].startswith("bundle--")
        # Still deterministic for an empty bundle.
        assert bundle["id"] == build_stix_bundle([], now=NOW)["id"]

    def test_generator_input_is_supported(self):
        def gen():
            for rec in SAMPLE_RECORDS:
                yield dict(rec)

        bundle = build_stix_bundle(gen(), now=NOW)
        assert len(_objects_by_type(bundle, "indicator")) == len(SAMPLE_RECORDS)

    def test_records_without_domain_are_skipped(self):
        records = [
            {"risk_score": 90},
            {"domain": ""},
            {"domain": "   "},
            {"domain": None},
            "not-a-dict",
            {"domain": "valid.example"},
        ]
        bundle = build_stix_bundle(records, now=NOW)
        indicators = _objects_by_type(bundle, "indicator")
        assert len(indicators) == 1
        assert indicators[0]["pattern"] == "[domain-name:value = 'valid.example']"


class TestIndicatorFields:
    """Tests for individual indicator content."""

    def test_full_indicator_fields(self):
        ind = _single_indicator(SAMPLE_RECORDS[0])
        domain = "nbk-secure-login.com"
        assert ind["type"] == "indicator"
        assert ind["spec_version"] == "2.1"
        assert ind["id"] == "indicator--" + str(uuid.uuid5(KCW_NAMESPACE, f"indicator:{domain}"))
        assert ind["name"] == f"Brand impersonation of National Banking Corporation (NBK): {domain}"
        assert ind["pattern"] == f"[domain-name:value = '{domain}']"
        assert ind["pattern_type"] == "stix"
        assert ind["pattern_version"] == "2.1"
        assert ind["created"] == "2026-09-01T08:00:00.000Z"
        assert ind["modified"] == "2026-09-20T09:15:30.250Z"
        assert ind["valid_from"] == ind["created"]
        assert ind["indicator_types"] == ["malicious-activity"]
        assert ind["confidence"] == 92
        assert ind["external_references"][0]["source_name"] == "certstream"
        assert ind["x_brandsentra_risk_score"] == pytest.approx(92.4)
        assert isinstance(ind["x_brandsentra_risk_score"], float)
        assert ind["x_brandsentra_risk_level"] == "critical"
        assert ind["x_brandsentra_brand"] == "National Banking Corporation (NBK)"
        assert ind["x_brandsentra_alert_type"] == "domain_squat"
        assert ind["x_brandsentra_matched_keywords"] == ["nbk", "login", "secure"]
        assert ind["description"]

    def test_labels_content(self):
        ind = _single_indicator(SAMPLE_RECORDS[0])
        assert ind["labels"] == sorted(
            {
                "brand_impersonation",
                "suspicious_keywords",
                "critical",
                "phishing",
                "brandsentra",
                "brand-impersonation",
            }
        )
        assert ind["labels"] == sorted(set(ind["labels"]))

        plain = _single_indicator({"domain": "plain.example", "categories": ["phishing", "x"]})
        assert plain["labels"] == ["brandsentra", "medium", "phishing", "x"]
        assert "brand-impersonation" not in plain["labels"]

    def test_minimal_record_defaults_and_absent_custom_props(self):
        ind = _single_indicator({"domain": "  Minimal.Example  "})
        assert ind["pattern"] == "[domain-name:value = 'minimal.example']"
        assert ind["name"] == "Suspected phishing domain: minimal.example"
        assert ind["x_brandsentra_risk_score"] == 50.0
        assert ind["x_brandsentra_risk_level"] == "medium"
        assert ind["confidence"] == 50
        assert ind["indicator_types"] == ["malicious-activity"]
        assert ind["created"] == ind["modified"] == ind["valid_from"] == stix_timestamp(NOW)
        assert "external_references" not in ind
        assert "x_brandsentra_brand" not in ind
        assert "x_brandsentra_alert_type" not in ind
        assert "x_brandsentra_matched_keywords" not in ind
        assert "minimal.example" in ind["description"]

    def test_pattern_escaping_of_quote_and_backslash(self):
        ind = _single_indicator({"domain": "we'ird\\dom.ain"})
        assert ind["pattern"] == "[domain-name:value = 'we\\'ird\\\\dom.ain']"

    @pytest.mark.parametrize(
        "score,expected_conf,expected_types,expected_level",
        [
            (150, 100, ["malicious-activity"], "critical"),
            (-20, 0, ["anomalous-activity"], "clean"),
            (49.6, 50, ["anomalous-activity"], "medium"),
            (50, 50, ["malicious-activity"], "medium"),
            (79.5, 80, ["malicious-activity"], "high"),
            ("64", 64, ["malicious-activity"], "high"),
            ("not-a-number", 50, ["malicious-activity"], "medium"),
        ],
    )
    def test_confidence_clamping_types_and_levels(
        self, score, expected_conf, expected_types, expected_level
    ):
        ind = _single_indicator({"domain": "score.example", "risk_score": score})
        assert ind["confidence"] == expected_conf
        assert 0 <= ind["confidence"] <= 100
        assert ind["indicator_types"] == expected_types
        assert ind["x_brandsentra_risk_level"] == expected_level

    def test_explicit_risk_level_is_respected(self):
        ind = _single_indicator({"domain": "lvl.example", "risk_score": 10, "risk_level": "HIGH"})
        assert ind["x_brandsentra_risk_level"] == "high"
        assert "high" in ind["labels"]

    def test_created_not_after_modified(self):
        # last_seen earlier than first_seen must be normalised.
        ind = _single_indicator(
            {
                "domain": "time.example",
                "first_seen": "2026-09-10T00:00:00Z",
                "last_seen": "2026-09-01T00:00:00Z",
            }
        )
        assert ind["created"] <= ind["modified"]
        assert ind["created"] == ind["modified"] == "2026-09-10T00:00:00.000Z"

        # Unparseable timestamps fall back to `now`.
        ind2 = _single_indicator({"domain": "t2.example", "first_seen": "yesterday-ish"})
        assert ind2["created"] == stix_timestamp(NOW)

        for obj in build_stix_bundle(SAMPLE_RECORDS, now=NOW)["objects"]:
            if obj["type"] == "indicator":
                assert obj["created"] <= obj["modified"]

    def test_timestamps_end_with_z_and_have_millisecond_precision(self):
        bundle = build_stix_bundle(SAMPLE_RECORDS, now=NOW)
        for obj in bundle["objects"]:
            for key in ("created", "modified", "valid_from"):
                if key in obj:
                    assert STIX_TS_RE.match(obj[key]), (obj["type"], key, obj[key])


class TestDeterminism:
    """Tests for stable identifiers and de-duplication."""

    def test_same_input_gives_same_ids(self):
        first = build_stix_bundle(SAMPLE_RECORDS, now=NOW)
        second = build_stix_bundle(list(reversed(SAMPLE_RECORDS)), now=NOW)
        assert first["id"] == second["id"]
        assert {o["id"] for o in first["objects"]} == {o["id"] for o in second["objects"]}

        # The indicator id depends only on the normalised domain.
        a = _single_indicator({"domain": "Dup.Example", "risk_score": 10})
        b = _single_indicator({"domain": "dup.example ", "risk_score": 90, "brand": "X"})
        assert a["id"] == b["id"]

    def test_different_domains_give_different_ids(self):
        a = _single_indicator({"domain": "one.example"})
        b = _single_indicator({"domain": "two.example"})
        assert a["id"] != b["id"]
        bundle_a = build_stix_bundle([{"domain": "one.example"}], now=NOW)
        bundle_b = build_stix_bundle([{"domain": "two.example"}], now=NOW)
        assert bundle_a["id"] != bundle_b["id"]

    def test_non_deterministic_bundle_id_changes(self):
        a = build_stix_bundle(SAMPLE_RECORDS, now=NOW, deterministic=False)
        b = build_stix_bundle(SAMPLE_RECORDS, now=NOW, deterministic=False)
        assert a["id"] != b["id"]
        assert uuid.UUID(a["id"].split("--", 1)[1]).version == 4

    def test_dedupe_keeps_highest_score(self):
        records = [
            {"domain": "dup.example", "risk_score": 40, "source": "scan"},
            {"domain": "DUP.example", "risk_score": 95, "source": "certstream"},
            {"domain": "dup.example", "risk_score": 60, "source": "squat_watcher"},
            {"domain": "other.example", "risk_score": 20},
        ]
        bundle = build_stix_bundle(records, now=NOW)
        indicators = _objects_by_type(bundle, "indicator")
        assert len(indicators) == 2
        dup = next(i for i in indicators if "dup.example" in i["pattern"])
        assert dup["confidence"] == 95
        assert dup["external_references"][0]["source_name"] == "certstream"


class TestSerialisation:
    """Tests for JSON output."""

    def test_json_round_trip(self):
        records = SAMPLE_RECORDS + [{"domain": "بنك-الكويت.com", "description": "عربي"}]
        bundle = build_stix_bundle(records, now=NOW)
        text = bundle_to_json(bundle)
        assert "بنك" in text  # ensure_ascii=False
        assert json.loads(text) == bundle

        compact = bundle_to_json(bundle, indent=None)
        assert "\n" not in compact
        assert json.loads(compact) == bundle

        # Key order is preserved (identity first, then marking, then indicators).
        parsed = json.loads(text)
        assert list(parsed.keys()) == ["type", "id", "objects"]
        assert list(parsed["objects"][2].keys())[:3] == ["type", "spec_version", "id"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
