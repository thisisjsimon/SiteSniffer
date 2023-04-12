#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
from __future__ import annotations

import datetime

import pytest

from src.sitesniffer import SiteSniffer
from src.sitesniffer.exceptions import SiteSnifferException

# pylint: disable=redefined-outer-name
# pylint: disable=missing-function-docstring


@pytest.fixture
def sniffer() -> SiteSniffer:
    return SiteSniffer("https://www.example.com/example/")


def test_invalid_url() -> None:
    with pytest.raises(SiteSnifferException):
        SiteSniffer("abc")


def test_extract_protocol(sniffer: SiteSniffer) -> None:
    assert sniffer.extract_protocol() == "https://"


def test_extract_hostname(sniffer: SiteSniffer) -> None:
    assert sniffer.extract_hostname() == "www.example.com"


def test_extract_path(sniffer: SiteSniffer) -> None:
    assert sniffer.extract_path() == "/example/"


def test_ip_address(sniffer: SiteSniffer) -> None:
    assert sniffer.ip_address() == "93.184.216.34"


def test_domain_info(sniffer: SiteSniffer) -> None:
    assert sniffer.domain_info().as_dict() == {
        "domain_name": "EXAMPLE.COM",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "whois_server": "whois.iana.org",
        "referral_url": None,
        "updated_date": datetime.datetime(2022, 8, 14, 7, 1, 31),
        "creation_date": datetime.datetime(1995, 8, 14, 4, 0),
        "expiration_date": datetime.datetime(2023, 8, 13, 4, 0),
        "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
        "status": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        ],
        "emails": None,
        "dnssec": "signedDelegation",
        "registrant_name": None,
        "registrant_organization": None,
        "registrant_street": None,
        "registrant_city": None,
        "registrant_state": None,
        "registrant_postal_code": None,
        "registrant_country": None,
        "admin_name": None,
        "admin_organization": None,
        "admin_street": None,
        "admin_city": None,
        "admin_state": None,
        "admin_postal_code": None,
        "admin_country": None,
        "tech_name": None,
        "tech_organization": None,
        "tech_street": None,
        "tech_city": None,
        "tech_state": None,
        "tech_postal_code": None,
        "tech_country": None,
        "abuse_contact_email": None,
        "abuse_contact_phone": None,
        "registrar_whois_server": None,
        "registrar_url": None,
        "registrar_abuse_contact_email": None,
        "registrar_abuse_contact_phone": None,
    }
    assert sniffer.domain_info().as_dict_without_none() == {
        "domain_name": "EXAMPLE.COM",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "whois_server": "whois.iana.org",
        "updated_date": datetime.datetime(2022, 8, 14, 7, 1, 31),
        "creation_date": datetime.datetime(1995, 8, 14, 4, 0),
        "expiration_date": datetime.datetime(2023, 8, 13, 4, 0),
        "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
        "status": [
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        ],
        "dnssec": "signedDelegation",
    }


def test_status_code(sniffer: SiteSniffer) -> None:
    assert sniffer.status_code() == 404


def test_ssl_info(sniffer: SiteSniffer) -> None:
    assert sniffer.ssl_info().as_dict() == {
        "subject": (
            (("countryName", "US"),),
            (("stateOrProvinceName", "California"),),
            (("localityName", "Los Angeles"),),
            (
                (
                    "organizationName",
                    "Internet\xa0Corporation\xa0for\xa0Assigned\xa0Names\xa0and\xa0Numbers",
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
        "serial_number": "0C1FCB184518C7E3866741236D6B73F1",
        "not_before": "Jan 13 00:00:00 2023 GMT",
        "not_after": "Feb 13 23:59:59 2024 GMT",
        "subject_alt_name": (
            ("DNS", "www.example.org"),
            ("DNS", "example.net"),
            ("DNS", "example.edu"),
            ("DNS", "example.com"),
            ("DNS", "example.org"),
            ("DNS", "www.example.com"),
            ("DNS", "www.example.edu"),
            ("DNS", "www.example.net"),
        ),
        "ocsp": ("http://ocsp.digicert.com",),
        "ca_issuers": (
            "http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt",
        ),
        "clr_distribution_points": (
            "http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
            "http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
        ),
    }


def test_load_time(sniffer: SiteSniffer) -> None:
    assert sniffer.load_time() > 0


def test_links(sniffer: SiteSniffer) -> None:
    assert sniffer.links() == ["https://www.iana.org/domains/example"]


def test_is_mobile_friendly(sniffer: SiteSniffer) -> None:
    assert sniffer.is_mobile_friendly() is False


def test_has_responsive_design(sniffer: SiteSniffer) -> None:
    assert sniffer.has_responsive_design() is True


def test_has_cookies(sniffer: SiteSniffer) -> None:
    assert sniffer.has_cookies() is False


def test_has_google_analytics(sniffer: SiteSniffer) -> None:
    assert sniffer.has_google_analytics() is False


def test_page_meta_description(sniffer: SiteSniffer) -> None:
    assert sniffer.page_meta_description() is None


def test_has_meta_description(sniffer: SiteSniffer) -> None:
    assert sniffer.has_meta_description() is False


def test_page_keywords(sniffer: SiteSniffer) -> None:
    assert sniffer.page_keywords() is None


def test_has_keywords(sniffer: SiteSniffer) -> None:
    assert sniffer.has_keywords() is False
