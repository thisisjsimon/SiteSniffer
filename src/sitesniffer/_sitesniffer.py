#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""Contains the SiteSniffer class."""
from __future__ import annotations

import re
import socket
import ssl
import time
from typing import Any, Literal, Optional
from urllib.parse import urljoin, urlparse

import bs4
import idna
import requests
import whois

from .data import DomainInfo, SSLCertInfo, WhoisEntry
from .exceptions import SiteSnifferException

__all__: list[str] = ["SiteSniffer"]

_URL_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:http|ftp)s?://"  # protocol
    r"(?:(?:[A-Z0-9_\u00a1-\uffff](?:[A-Z0-9-_\u00a1-\uffff]{0,61}[A-Z0-9_\u00a1-\uffff])?\.)+(?:[A-Z0-9-_\u00a1-\uffff]{2,}\.?)|"  # domain with IDN support
    r"localhost|"  # localhost
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # IP address
    r"(?::\d+)?"  # port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,  # case insensitive
)

_URL_GROUPS: re.Pattern[str] = re.compile(
    r"(?P<protocol>https?://)?(?P<hostname>[^/]+)(?P<path>/.*)?",
)


class SiteSniffer:
    """A class for extracting information about a website, such as its IP address, SSL certificate information, and
    load time.

    Attributes:
        ``url: str``

    Methods:
        ``extract_protocol() -> str``

        ``extract_hostname() -> str``

        ``extract_path() -> str``

        ``ip_address() -> str``

        ``domain_info() -> DomainInfo``

        ``status_code(*, timeout: int = 10) -> int``

        ``ssl_info() -> SSLCertInfo``

        ``load_time(*, timeout: int = 10) -> float``

        ``links(*, timeout: int = 10) -> list[str]``

        ``is_mobile_friendly(*, timeout: int = 10) -> bool``

        ``has_responsive_design(*, timeout: int = 10) -> bool``

        ``has_cookies(*, timeout: int = 10) -> bool``

        ``has_google_analytics(*, timeout: int = 10) -> bool``

        ``page_meta_description(*, timeout: int = 10) -> str | list[str] | Any``

        ``has_meta_description(*, timeout: int = 10) -> bool``

        ``page_keywords(*, timeout: int = 10) -> str | list[str] | Any``

        ``has_keywords(*, timeout: int = 10) -> bool``

    The ``timeout`` argument sets the maximum amount of time in seconds that a request is allowed to take before it times out and raises an exception, by default 10 seconds.

    Example:
    >>> sniffer: SiteSniffer = SiteSniffer("https://www.example.com/example/")
    >>> sniffer.extract_hostname()
    'www.example.com'
    >>> sniffer.ip_address()
    '93.184.216.34'

    For more documentation go to https://github.com/thisisjsimon/SiteSniffer
    """

    __slots__: tuple[Literal["__dict__"], Literal["_url"]] = ("__dict__", "_url")

    def __init__(self, url: str) -> None:
        if not re.match(_URL_PATTERN, url):
            raise SiteSnifferException(f"Invalid URL: {url}")
        self._url: str = url

    def __hash__(self) -> int:
        return hash((self.__class__, self.url))

    def __eq__(self, other: object) -> bool:
        """Returns True if other is a SiteSniffer instance with the same URL."""
        if not isinstance(other, self.__class__):
            return False
        return self.url == other.url

    def __reduce__(self) -> tuple[type[SiteSniffer], tuple[str]]:
        return self.__class__, (self.url,)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(url={self.url!r})"

    @property
    def url(self) -> str:
        """Returns the URL."""
        return self._url

    def _extract_from_pattern(self, capture_group: str) -> str:
        re_match: Optional[re.Match[str]] = re.match(_URL_GROUPS, self.url)
        if not re_match:
            raise SiteSnifferException(f"Unable to exctract hostname from {self.url}")
        return re_match.group(capture_group)

    def extract_protocol(self) -> str:
        """Extracts the protocol from the URL."""
        return self._extract_from_pattern("protocol")

    def extract_hostname(self) -> str:
        """Extracts the hostname from the URL."""
        return self._extract_from_pattern("hostname")

    def extract_path(self) -> str:
        """Extracts the path from the URL."""
        return self._extract_from_pattern("path")

    def ip_address(self) -> dict:
        domain = urlparse(self.url).netloc
        ip_addresses = {}
        for result in socket.getaddrinfo(domain, 0, flags=socket.AI_CANONNAME):
            ip_version = result[0]
            ip_address = result[4][0]
            if ip_version == socket.AF_INET:
                ip_addresses["ipv4"] = ip_address
            elif ip_version == socket.AF_INET6:
                ip_addresses["ipv6"] = ip_address
        return ip_addresses

    def domain_info(self) -> DomainInfo:
        """Returns the domain information for the website."""
        whois_entry: WhoisEntry = whois.whois(self.url)
        return DomainInfo(
            domain_name=getattr(whois_entry, "domain_name", None),
            registrar=getattr(whois_entry, "registrar", None),
            whois_server=getattr(whois_entry, "whois_server", None),
            referral_url=getattr(whois_entry, "referral_url", None),
            updated_date=getattr(whois_entry, "updated_date", None),
            creation_date=getattr(whois_entry, "creation_date", None),
            expiration_date=getattr(whois_entry, "expiration_date", None),
            name_servers=getattr(whois_entry, "name_servers", None),
            status=getattr(whois_entry, "status", None),
            emails=getattr(whois_entry, "emails", None),
            dnssec=getattr(whois_entry, "dnssec", None),
            registrant_name=getattr(whois_entry, "registrant_name", None),
            registrant_organization=getattr(whois_entry, "registrant_organization", None),
            registrant_street=getattr(whois_entry, "registrant_street", None),
            registrant_city=getattr(whois_entry, "registrant_city", None),
            registrant_state=getattr(whois_entry, "registrant_state", None),
            registrant_postal_code=getattr(whois_entry, "registrant_postal_code", None),
            registrant_country=getattr(whois_entry, "registrant_country", None),
            admin_name=getattr(whois_entry, "admin_name", None),
            admin_organization=getattr(whois_entry, "admin_organization", None),
            admin_street=getattr(whois_entry, "admin_street", None),
            admin_city=getattr(whois_entry, "admin_city", None),
            admin_state=getattr(whois_entry, "admin_state", None),
            admin_postal_code=getattr(whois_entry, "admin_postal_code", None),
            admin_country=getattr(whois_entry, "admin_country", None),
            tech_name=getattr(whois_entry, "tech_name", None),
            tech_organization=getattr(whois_entry, "tech_organization", None),
            tech_street=getattr(whois_entry, "tech_street", None),
            tech_city=getattr(whois_entry, "tech_city", None),
            tech_state=getattr(whois_entry, "tech_state", None),
            tech_postal_code=getattr(whois_entry, "tech_postal_code", None),
            tech_country=getattr(whois_entry, "tech_country", None),
            abuse_contact_email=getattr(whois_entry, "abuse_contact_email", None),
            abuse_contact_phone=getattr(whois_entry, "abuse_contact_phone", None),
            registrar_whois_server=getattr(whois_entry, "registrar_whois_server", None),
            registrar_url=getattr(whois_entry, "registrar_url", None),
            registrar_abuse_contact_email=getattr(whois_entry, "registrar_abuse_contact_email", None),
            registrar_abuse_contact_phone=getattr(whois_entry, "registrar_abuse_contact_phone", None),
        )

    def status_code(self, *, timeout: int = 10) -> int:
        """Returns the HTTP status code of the URL."""
        return requests.get(self.url, timeout=timeout).status_code

    def ssl_info(self) -> SSLCertInfo:
        """Returns SSL certificate information for the domain if fetchable otherwise it throws an exception."""
        hostname: str = self.extract_hostname()
        # encode hostname using Punycode if it contains non-ASCII characters
        hostname = idna.encode(hostname).decode("utf-8")
        with socket.create_connection(
            (hostname, 443),
        ) as sock, ssl.create_default_context().wrap_socket(
            sock,
            server_hostname=hostname,
        ) as ssl_sock:
            ssl_info_dict: Optional[ssl._PeerCertRetDictType] = ssl_sock.getpeercert()

        if not ssl_info_dict:
            raise SiteSnifferException(
                f"Unable to fetch SSL certificate information from the given domain: {self.url}",
            )

        return SSLCertInfo(
            subject=ssl_info_dict["subject"],
            issuer=ssl_info_dict["issuer"],
            version=ssl_info_dict["version"],
            serial_number=ssl_info_dict["serialNumber"],
            not_before=ssl_info_dict["notBefore"],
            not_after=ssl_info_dict["notAfter"],
            subject_alt_name=ssl_info_dict["subjectAltName"],
            ocsp=ssl_info_dict["OCSP"],
            ca_issuers=ssl_info_dict["caIssuers"],
            clr_distribution_points=ssl_info_dict["crlDistributionPoints"],
        )

    def load_time(self, *, ndigits: int = 3, timeout: int = 10) -> float:
        """Returns the load time for the website and its sub-pages."""
        start_time: float = time.perf_counter()

        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.content, "html.parser")
        for img in soup.find_all("img"):
            src = img.get("src")
            if src:
                requests.get(urljoin(self.url, str(src)), timeout=timeout)

        end_time: float = time.perf_counter()

        return round(end_time - start_time, ndigits=ndigits)

    def links(self, *, timeout: int = 10) -> list[str]:
        """Returns a list of URLs on the page."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        valid_hrefs: list[str] = [
            str(link.get("href")) for link in soup.find_all("a") if link.get("href")
        ]
        return [
            href
            if href.startswith("http") or href.startswith(self.url)
            else self.extract_protocol() + self.extract_hostname() + href
            for href in valid_hrefs
        ]

    def is_mobile_friendly(self, *, timeout: int = 10) -> bool:
        """Checks whether the website is mobile friendly (not as reliable)."""
        headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        }
        return (
            requests.get(self.url, headers=headers, timeout=timeout).status_code == 200
        )

    def has_responsive_design(self, *, timeout: int = 10) -> bool:
        """Checks whether the website is using a responsive design."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        return any(
            "viewport" in str(tag.get("name", "")).lower() for tag in soup.find_all("meta")
        )

    def has_cookies(self, *, timeout: int = 10) -> bool:
        """Checks whether the website is using cookies (not as reliable)."""
        return "Set-Cookie" in requests.get(self.url, timeout=timeout).headers

    def has_google_analytics(self, *, timeout: int = 10) -> bool:
        """Checks whether the website is using Google Analytics."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        return any(
            any(
                ga in str(tag.get("src", "")).lower()
                for ga in (
                    "google-analytics.com/analytics.js",
                    "googletagmanager.com/gtag/js",
                    "google-analytics.com/ga.js",
                )
            )
            for tag in soup.find_all("script")
        )

    def page_meta_description(
        self,
        *,
        timeout: int = 10,
    ) -> str | list[str] | Any:
        """Returns the meta description for the webpage, given its URL."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        meta_description: Optional[bs4.Tag] = soup.find(
            "meta",
            attrs={"name": re.compile(r"^description$", re.IGNORECASE)},
        )
        if meta_description and meta_description.get("content") is not None:
            return meta_description.get("content")
        return []

    def has_meta_description(self, *, timeout: int = 10) -> bool:
        """Checks whether the website has a meta description."""
        return bool(self.page_meta_description(timeout=timeout))

    def page_keywords(self, *, timeout: int = 10) -> str | list[str] | Any:
        """Returns the meta keywords for the webpage, given its URL."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        meta_keywords: Optional[bs4.Tag] = soup.find(
            "meta",
            attrs={"name": re.compile(r"^keywords$", re.IGNORECASE)},
        )
        if meta_keywords and meta_keywords.get("content") is not None:
            return meta_keywords.get("content")
        return []

    def has_keywords(self, *, timeout: int = 10) -> bool:
        """Checks whether the website has keywords."""
        return bool(self.page_keywords(timeout=timeout))

