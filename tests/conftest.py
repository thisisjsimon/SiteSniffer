from __future__ import annotations

import datetime
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Ensure src directory is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sitesniffer import SiteSniffer


@pytest.fixture
def sample_url() -> str:
    return "https://www.example.com/example/"


@pytest.fixture
def sniffer(sample_url: str) -> SiteSniffer:
    return SiteSniffer(sample_url)


@pytest.fixture
def sample_ssl_cert_dict() -> dict[str, Any]:
    """Sample dictionary returned by ssl_sock.getpeercert()."""
    return {
        "subject": (
            (("countryName", "US"),),
            (("stateOrProvinceName", "California"),),
            (("localityName", "Los Angeles"),),
            (
                (
                    "organizationName",
                    "Internet Corporation for Assigned Names and Numbers",
                ),
            ),
            (("commonName", "www.example.org"),),
        ),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "DigiCert Inc"),),
            (("commonName", "DigiCert TLS RSA SHA256 2020 CA1"),),
        ),
        "version": 3,
        "serialNumber": "0C1FCB184518C7E3866741236D6B73F1",
        "notBefore": "Jan 13 00:00:00 2023 GMT",
        "notAfter": "Feb 13 23:59:59 2024 GMT",
        "subjectAltName": (
            ("DNS", "www.example.org"),
            ("DNS", "example.net"),
            ("DNS", "example.edu"),
            ("DNS", "example.com"),
            ("DNS", "example.org"),
            ("DNS", "www.example.com"),
            ("DNS", "www.example.edu"),
            ("DNS", "www.example.net"),
        ),
        "OCSP": ("http://ocsp.digicert.com",),
        "caIssuers": (
            "http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt",
        ),
        "crlDistributionPoints": (
            "http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
            "http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
        ),
    }


@pytest.fixture
def sample_whois_entry() -> MagicMock:
    """Sample WhoisEntry object populated with known mock data."""
    mock_whois = MagicMock()
    mock_whois.domain_name = "EXAMPLE.COM"
    mock_whois.registrar = "RESERVED-Internet Assigned Numbers Authority"
    mock_whois.whois_server = "whois.iana.org"
    mock_whois.referral_url = None
    mock_whois.updated_date = datetime.datetime(2023, 8, 14, 7, 1, 38, tzinfo=datetime.timezone.utc)
    mock_whois.creation_date = datetime.datetime(1995, 8, 14, 4, 0, tzinfo=datetime.timezone.utc)
    mock_whois.expiration_date = datetime.datetime(2024, 8, 13, 4, 0, tzinfo=datetime.timezone.utc)
    mock_whois.name_servers = ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    mock_whois.status = [
        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
    ]
    mock_whois.emails = None
    mock_whois.dnssec = "signedDelegation"
    mock_whois.registrant_name = None
    mock_whois.registrant_organization = None
    mock_whois.registrant_street = None
    mock_whois.registrant_city = None
    mock_whois.registrant_state = None
    mock_whois.registrant_postal_code = None
    mock_whois.registrant_country = None
    mock_whois.admin_name = None
    mock_whois.admin_organization = None
    mock_whois.admin_street = None
    mock_whois.admin_city = None
    mock_whois.admin_state = None
    mock_whois.admin_postal_code = None
    mock_whois.admin_country = None
    mock_whois.tech_name = None
    mock_whois.tech_organization = None
    mock_whois.tech_street = None
    mock_whois.tech_city = None
    mock_whois.tech_state = None
    mock_whois.tech_postal_code = None
    mock_whois.tech_country = None
    mock_whois.abuse_contact_email = None
    mock_whois.abuse_contact_phone = None
    mock_whois.registrar_whois_server = None
    mock_whois.registrar_url = None
    mock_whois.registrar_abuse_contact_email = None
    mock_whois.registrar_abuse_contact_phone = None
    return mock_whois


@pytest.fixture
def rich_html_content() -> str:
    """Sample full-featured HTML document containing various tags."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="This is an example website meta description.">
    <meta name="keywords" content="example, sitesniffer, testing, python">
    <title>Example Domain</title>
    <script src="https://www.google-analytics.com/analytics.js" async></script>
</head>
<body>
    <h1>Example Heading</h1>
    <p>Some text</p>
    <img src="/images/logo.png" alt="Logo">
    <img src="https://cdn.example.com/banner.jpg" alt="Banner">
    <a href="https://www.iana.org/domains/example">External Link</a>
    <a href="/about/">Relative Link</a>
    <a href="contact.html">Another Relative Link</a>
    <a href="https://www.example.com/example/subpage">Subpage Link</a>
    <a>Anchor without href</a>
</body>
</html>"""


@pytest.fixture
def empty_html_content() -> str:
    """Minimal HTML document with no meta, links, images or analytics."""
    return "<!DOCTYPE html><html><head><title>Bare</title></head><body><p>Hello</p></body></html>"
