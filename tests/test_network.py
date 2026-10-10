#!/usr/bin/env python3
"""Tests for src/utils/network.py (offline)."""

from src.utils import network

RDAP_DOC = {
    "handle": "123",
    "ldhName": "NBK-LOGIN.COM",
    "status": ["client transfer prohibited"],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "ns2.example.net"}],
    "secureDNS": {"delegationSigned": False},
    "events": [
        {"eventAction": "registration", "eventDate": "2026-09-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-09-01T00:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-09-02T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cheap Registrar LLC"]],
            ],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@cheap.example"]]],
                }
            ],
        }
    ],
}


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_parse_rdap():
    info = network.parse_rdap(RDAP_DOC)
    assert info["registrar"] == "Cheap Registrar LLC"
    assert info["abuse_email"] == "abuse@cheap.example"
    assert info["nameservers"] == ["ns1.example.net", "ns2.example.net"]
    assert info["created"] == "2026-09-01T00:00:00Z"
    assert info["expires"].startswith("2027")
    assert info["age_days"] is not None and info["age_days"] >= 0
    assert info["dnssec"] is False


def test_rdap_lookup_uses_registrable_domain():
    session = FakeSession(FakeResponse(200, RDAP_DOC))
    info = network.rdap_lookup("https://login.nbk-login.com/x", session=session)
    assert session.calls[0][0] == "https://rdap.org/domain/nbk-login.com"
    assert info["registered"] is True and info["registrar"] == "Cheap Registrar LLC"


def test_rdap_lookup_not_found_and_errors():
    assert network.rdap_lookup("nope.example", session=FakeSession(FakeResponse(404))) == {
        "ldh_name": "nope.example",
        "registered": False,
    }
    assert network.rdap_lookup("x.example", session=FakeSession(FakeResponse(500))) is None
    assert network.rdap_lookup("x.example", session=FakeSession(RuntimeError("boom"))) is None
    assert network.rdap_lookup("") is None


def test_enrich_domain_with_injected_lookups():
    result = network.enrich_domain(
        "NBK-login.com",
        whois=True,
        lookups={
            "dns": lambda d: {"A": ["1.2.3.4"], "AAAA": []},
            "rdap": lambda d: {"registrar": "R"},
            "tls": lambda d: (_ for _ in ()).throw(RuntimeError("tls down")),
            "whois": lambda d: None,
        },
    )
    assert result["domain"] == "nbk-login.com"
    assert result["dns"]["A"] == ["1.2.3.4"]
    assert result["resolves"] is True
    assert result["rdap"]["registrar"] == "R"
    assert result["tls"] is None and result["errors"]["tls"] == "tls down"
    assert result["whois"] is None


def test_enrich_domain_disabled_steps():
    result = network.enrich_domain("x.example", dns=False, rdap=False, tls=False)
    assert result["resolves"] is None
    assert "dns" not in result and "rdap" not in result


def test_normalise_cert():
    cert = {
        "subject": ((("commonName", "nbk-login.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "serialNumber": "AB",
        "notBefore": "Jan 1 00:00:00 2026 GMT",
        "notAfter": "Apr 1 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "nbk-login.com"), ("DNS", "www.nbk-login.com")),
    }
    info = network._normalise_cert(cert)
    assert info["issuer"]["organizationName"] == "Let's Encrypt"
    assert info["san"] == ["nbk-login.com", "www.nbk-login.com"]


def test_dns_resolve_handles_failures(monkeypatch):
    class FakeRecord:
        def __str__(self):
            return "1.1.1.1"

    class FakeResolver:
        timeout = 0
        lifetime = 0

        def resolve(self, domain, rtype):
            if rtype == "A":
                return [FakeRecord()]
            raise fake_dns.resolver.NoAnswer()

    import types

    fake_dns = types.ModuleType("dns")
    fake_dns.resolver = types.ModuleType("dns.resolver")

    class NoAnswer(Exception):
        pass

    fake_dns.resolver.NoAnswer = NoAnswer
    fake_dns.resolver.NXDOMAIN = type("NXDOMAIN", (Exception,), {})
    fake_dns.resolver.NoNameservers = type("NoNameservers", (Exception,), {})
    fake_dns.resolver.Resolver = FakeResolver
    monkeypatch.setitem(__import__("sys").modules, "dns", fake_dns)
    monkeypatch.setitem(__import__("sys").modules, "dns.resolver", fake_dns.resolver)
    records = network.dns_resolve("example.com")
    assert records["A"] == ["1.1.1.1"]
    assert records["MX"] == []
    assert network.resolve_ips("example.com") == ["1.1.1.1"]
