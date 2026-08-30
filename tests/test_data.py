from __future__ import annotations

import datetime

import pytest

import sitesniffer.data as data_mod
from sitesniffer.data import DomainInfo, SSLCertInfo


def test_data_module_metadata() -> None:
    """Verify data module exports."""
    assert data_mod.__all__ == ["DomainInfo", "SSLCertDictEntry", "SSLCertInfo", "WhoisEntry"]


def test_domain_info_fields_and_types() -> None:
    """Verify DomainInfo NamedTuple fields count, names, and inheritance."""
    assert issubclass(DomainInfo, tuple)
    assert hasattr(DomainInfo, "_fields")

    expected_fields = (
        "domain_name",
        "registrar",
        "whois_server",
        "referral_url",
        "updated_date",
        "creation_date",
        "expiration_date",
        "name_servers",
        "status",
        "emails",
        "dnssec",
        "registrant_name",
        "registrant_organization",
        "registrant_street",
        "registrant_city",
        "registrant_state",
        "registrant_postal_code",
        "registrant_country",
        "admin_name",
        "admin_organization",
        "admin_street",
        "admin_city",
        "admin_state",
        "admin_postal_code",
        "admin_country",
        "tech_name",
        "tech_organization",
        "tech_street",
        "tech_city",
        "tech_state",
        "tech_postal_code",
        "tech_country",
        "abuse_contact_email",
        "abuse_contact_phone",
        "registrar_whois_server",
        "registrar_url",
        "registrar_abuse_contact_email",
        "registrar_abuse_contact_phone",
    )
    assert DomainInfo._fields == expected_fields
    assert len(DomainInfo._fields) == 38


def test_domain_info_instantiation_and_asdict() -> None:
    """Verify DomainInfo dictionary schema and _asdict_without_none method."""
    updated = datetime.datetime(2023, 8, 14, 7, 1, 38, tzinfo=datetime.timezone.utc)
    created = datetime.datetime(1995, 8, 14, 4, 0, tzinfo=datetime.timezone.utc)
    expires = datetime.datetime(2024, 8, 13, 4, 0, tzinfo=datetime.timezone.utc)
    name_servers = ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    status = ["clientDeleteProhibited"]

    info = DomainInfo(
        domain_name="EXAMPLE.COM",
        registrar="RESERVED-IANA",
        whois_server="whois.iana.org",
        referral_url=None,
        updated_date=updated,
        creation_date=created,
        expiration_date=expires,
        name_servers=name_servers,
        status=status,
        emails=None,
        dnssec="signedDelegation",
        registrant_name=None,
        registrant_organization=None,
        registrant_street=None,
        registrant_city=None,
        registrant_state=None,
        registrant_postal_code=None,
        registrant_country=None,
        admin_name=None,
        admin_organization=None,
        admin_street=None,
        admin_city=None,
        admin_state=None,
        admin_postal_code=None,
        admin_country=None,
        tech_name=None,
        tech_organization=None,
        tech_street=None,
        tech_city=None,
        tech_state=None,
        tech_postal_code=None,
        tech_country=None,
        abuse_contact_email=None,
        abuse_contact_phone=None,
        registrar_whois_server=None,
        registrar_url=None,
        registrar_abuse_contact_email=None,
        registrar_abuse_contact_phone=None,
    )

    # Verify field access
    assert info.domain_name == "EXAMPLE.COM"
    assert info.registrar == "RESERVED-IANA"
    assert info.whois_server == "whois.iana.org"
    assert info.referral_url is None
    assert info.updated_date == updated
    assert info.creation_date == created
    assert info.expiration_date == expires
    assert info.name_servers == name_servers
    assert info.status == status
    assert info.dnssec == "signedDelegation"
    assert info.tech_name is None

    # Verify NamedTuple index access and immutability
    assert info[0] == "EXAMPLE.COM"
    with pytest.raises(AttributeError):
        info.domain_name = "ANOTHER.COM"  # type: ignore[misc]

    # Verify _asdict() returns all 38 keys
    as_dict = info._asdict()
    assert isinstance(as_dict, dict)
    assert len(as_dict) == 38
    assert as_dict["domain_name"] == "EXAMPLE.COM"
    assert as_dict["referral_url"] is None
    assert as_dict["tech_name"] is None

    # Verify _asdict_without_none() filters out None keys
    filtered = info._asdict_without_none()
    assert isinstance(filtered, dict)
    assert filtered == {
        "domain_name": "EXAMPLE.COM",
        "registrar": "RESERVED-IANA",
        "whois_server": "whois.iana.org",
        "updated_date": updated,
        "creation_date": created,
        "expiration_date": expires,
        "name_servers": name_servers,
        "status": status,
        "dnssec": "signedDelegation",
    }
    assert "referral_url" not in filtered
    assert "tech_name" not in filtered
    assert "admin_name" not in filtered


def test_domain_info_all_none() -> None:
    """Verify DomainInfo when all values are None."""
    info = DomainInfo(*(None for _ in range(38)))
    assert len(info._asdict()) == 38
    assert info._asdict_without_none() == {}


def test_ssl_cert_info_fields_and_types(sample_ssl_cert_dict: dict) -> None:
    """Verify SSLCertInfo NamedTuple fields count, names, types, and schema."""
    assert issubclass(SSLCertInfo, tuple)
    assert hasattr(SSLCertInfo, "_fields")

    expected_fields = (
        "subject",
        "issuer",
        "version",
        "serial_number",
        "not_before",
        "not_after",
        "subject_alt_name",
        "ocsp",
        "ca_issuers",
        "clr_distribution_points",
    )
    assert SSLCertInfo._fields == expected_fields
    assert len(SSLCertInfo._fields) == 10

    cert_info = SSLCertInfo(
        subject=sample_ssl_cert_dict["subject"],
        issuer=sample_ssl_cert_dict["issuer"],
        version=sample_ssl_cert_dict["version"],
        serial_number=sample_ssl_cert_dict["serialNumber"],
        not_before=sample_ssl_cert_dict["notBefore"],
        not_after=sample_ssl_cert_dict["notAfter"],
        subject_alt_name=sample_ssl_cert_dict["subjectAltName"],
        ocsp=sample_ssl_cert_dict["OCSP"],
        ca_issuers=sample_ssl_cert_dict["caIssuers"],
        clr_distribution_points=sample_ssl_cert_dict["crlDistributionPoints"],
    )

    assert cert_info.subject == sample_ssl_cert_dict["subject"]
    assert cert_info.issuer == sample_ssl_cert_dict["issuer"]
    assert cert_info.version == 3
    assert isinstance(cert_info.version, int)
    assert cert_info.serial_number == "0C1FCB184518C7E3866741236D6B73F1"
    assert cert_info.not_before == "Jan 13 00:00:00 2023 GMT"
    assert cert_info.not_after == "Feb 13 23:59:59 2024 GMT"
    assert cert_info.subject_alt_name == sample_ssl_cert_dict["subjectAltName"]
    assert cert_info.ocsp == ("http://ocsp.digicert.com",)
    assert cert_info.ca_issuers == ("http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt",)
    assert cert_info.clr_distribution_points == (
        "http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
        "http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
    )

    # Immutability
    with pytest.raises(AttributeError):
        cert_info.version = 4  # type: ignore[misc]

    # asdict schema
    as_dict = cert_info._asdict()
    assert isinstance(as_dict, dict)
    assert len(as_dict) == 10
    assert list(as_dict.keys()) == list(expected_fields)
