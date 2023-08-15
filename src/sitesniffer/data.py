#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""This module defines a dataclass named DomainInfo, which contains domain registration information.
The class has five attributes, all of which are of the same type: WhoisEntry. WhoisEntry is a type alias for Any, which means it can be any Python object.
"""
from __future__ import annotations

from typing import Any, Iterator, TypeAlias, Optional, NamedTuple

__all__: list = ["DomainInfo", "SSLCertInfo", "WhoisEntry", "SSLCertDictEntry"]

WhoisEntry: TypeAlias = Any  # TypeAlias for type readability
SSLCertDictEntry: TypeAlias = (
    str | tuple[tuple[str, str], ...] | tuple[tuple[tuple[str, str], ...], ...]
)


class DomainInfo(NamedTuple):
    """Dataclass containing the domain information.

    Some of the information may be marked as ``None`` depending on the domain.
    """

    domain_name: Optional[WhoisEntry]
    registrar: Optional[WhoisEntry]
    whois_server: Optional[WhoisEntry]
    referral_url: Optional[WhoisEntry]
    updated_date: Optional[WhoisEntry]
    creation_date: Optional[WhoisEntry]
    expiration_date: Optional[WhoisEntry]
    name_servers: Optional[WhoisEntry]
    status: Optional[WhoisEntry]
    emails: Optional[WhoisEntry]
    dnssec: Optional[WhoisEntry]
    registrant_name: Optional[WhoisEntry]
    registrant_organization: Optional[WhoisEntry]
    registrant_street: Optional[WhoisEntry]
    registrant_city: Optional[WhoisEntry]
    registrant_state: Optional[WhoisEntry]
    registrant_postal_code: Optional[WhoisEntry]
    registrant_country: Optional[WhoisEntry]
    admin_name: Optional[WhoisEntry]
    admin_organization: Optional[WhoisEntry]
    admin_street: Optional[WhoisEntry]
    admin_city: Optional[WhoisEntry]
    admin_state: Optional[WhoisEntry]
    admin_postal_code: Optional[WhoisEntry]
    admin_country: Optional[WhoisEntry]
    tech_name: Optional[WhoisEntry]
    tech_organization: Optional[WhoisEntry]
    tech_street: Optional[WhoisEntry]
    tech_city: Optional[WhoisEntry]
    tech_state: Optional[WhoisEntry]
    tech_postal_code: Optional[WhoisEntry]
    tech_country: Optional[WhoisEntry]
    abuse_contact_email: Optional[WhoisEntry]
    abuse_contact_phone: Optional[WhoisEntry]
    registrar_whois_server: Optional[WhoisEntry]
    registrar_url: Optional[WhoisEntry]
    registrar_abuse_contact_email: Optional[WhoisEntry]
    registrar_abuse_contact_phone: Optional[WhoisEntry]

    def _asdict_without_none(self) -> dict[str, WhoisEntry]:
        """Returns the dataclass a a dictionary but with all the ``None`` value-keys missing."""
        return {key: val for key, val in self._asdict().items() if val is not None}


class SSLCertInfo(NamedTuple):
    """Dataclass containing the SSL certificate information."""

    subject: SSLCertDictEntry
    issuer: SSLCertDictEntry
    version: SSLCertDictEntry
    serial_number: SSLCertDictEntry
    not_before: SSLCertDictEntry
    not_after: SSLCertDictEntry
    subject_alt_name: SSLCertDictEntry
    ocsp: SSLCertDictEntry
    ca_issuers: SSLCertDictEntry
    clr_distribution_points: SSLCertDictEntry
