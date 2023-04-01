# -*- coding: UTF-8 -*-
from __future__ import annotations

import re
import socket
import ssl
import time
from typing import Any, Literal, Optional, Self
from urllib.parse import urljoin, urlparse

import bs4
import idna
import requests
import whois

from .data import DomainInfo, WhoisEntry
from .exceptions import SiteSnifferException

__all__: list[str] = ["SiteSniffer"]

_URL_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:http|ftp)s?://"  # scheme
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain
    r"localhost|"  # localhost
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # IP address
    r"(?::\d+)?"  # port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
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
        ``extract_protocol(url: str, /) -> str``

        ``extract_hostname(url: str, /) -> str``

        ``extract_path(url: str, /) -> str``

        ``ip_address(self, /) -> str``

        ``domain_info(self, /) -> DomainInfo``

        ``status_code(self, /, *, timeout: int = 10) -> int``

        ``ssl_info(self, /) -> Optional[ssl._PeerCertRetDictType]``

        ``load_time(self, /, *, timeout: int = 10) -> float``

        ``links(self, /, *, timeout: int = 10) -> list[str]``

        ``is_mobile_friendly(self, /, *, timeout: int = 10) -> bool``

        ``has_responsive_design(self, /, *, timeout: int = 10) -> bool``

        ``has_cookies(self, /, *, timeout: int = 10) -> bool``

        ``has_google_analytics(self, /, *, timeout: int = 10) -> bool``

        ``page_meta_description(self, /, *, timeout: int = 10) -> Optional[str | list[str] | Any]``

        ``has_meta_description(self, /, *, timeout: int = 10) -> bool``

        ``page_keywords(self, /, *, timeout: int = 10) -> Optional[str | list[str] | Any]``

        ``has_keywords(self, /, *, timeout: int = 10) -> bool``

    For more documentation go to https://github.com/thisisjsimon/SiteSniffer
    """

    __slots__: tuple[Literal["__url"]] = ("__url",)

    def __init__(self, url: str) -> None:
        if not re.match(_URL_PATTERN, url):
            raise SiteSnifferException(f"Invalid URL: {url}")
        self.__url: str = url

    def __hash__(self) -> int:
        return hash(self.url)

    def __reduce__(self) -> tuple[type[Self], tuple[str]]:
        return self.__class__, (self.url,)

    def __repr__(self, /) -> str:
        return f"{self.__class__.__name__}(url={self.url!r})"

    @property
    def url(self, /) -> str:
        """Returns the URL."""
        return self.__url

    def _extract_from_pattern(self, capture_group: str) -> str:
        re_match: Optional[re.Match[str]] = re.match(_URL_GROUPS, self.url)
        print(re_match)
        if not re_match:
            raise SiteSnifferException(f"Unable to exctract hostname from {self.url}")
        return re_match.group(capture_group)

    def extract_protocol(self, /) -> str:
        """Extracts the protocol from the URL."""
        return self._extract_from_pattern("protocol")

    def extract_hostname(self, /) -> str:
        """Extracts the hostname from the URL."""
        return self._extract_from_pattern("hostname")

    def extract_path(self, /) -> str:
        """Extracts the path from the URL."""
        return self._extract_from_pattern("path")

    def ip_address(self, /) -> str:
        """Returns the IP address of the domain."""
        domain: str = urlparse(self.url).netloc
        return socket.gethostbyname(domain)

    def domain_info(self, /) -> DomainInfo:
        """Returns the domain information for the website."""
        whois_entry: WhoisEntry = whois.whois(self.url)
        return DomainInfo(
            name=whois_entry.domain_name,
            registrar=whois_entry.registrar,
            creation_date=whois_entry.creation_date,
            expiration_date=whois_entry.expiration_date,
            last_updated=whois_entry.last_updated,
        )

    def status_code(self, /, *, timeout: int = 10) -> int:
        """Returns the HTTP status code of a URL."""
        return requests.get(self.url, timeout=timeout).status_code

    def ssl_info(self, /) -> Optional[ssl._PeerCertRetDictType]:  # noqa: SLF001
        """Returns SSL certificate information for a domain."""
        hostname: str = self.extract_hostname()
        # encode hostname using Punycode if it contains non-ASCII characters
        hostname = idna.encode(hostname).decode("utf-8")
        with socket.create_connection(
            (hostname, 443),
        ) as sock, ssl.create_default_context().wrap_socket(
            sock,
            server_hostname=hostname,
        ) as ssl_sock:
            return ssl_sock.getpeercert()

    def load_time(self, /, *, timeout: int = 10) -> float:
        """Returns the load time for the website and its sub-pages."""
        start_time: float = time.perf_counter()
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.content, "html.parser")

        for img in soup.find_all("img"):
            requests.get(urljoin(self.url, img["src"]), timeout=timeout)
        end_time: float = time.perf_counter()

        return end_time - start_time

    def links(self, /, *, timeout: int = 10) -> list[str]:
        """Returns a list of URLs on the page."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        return [
            link.get("href")
            if link.get("href").startswith("http")
            and link.get("href").startswith(self.url)
            else self.url + link.get("href")
            for link in soup.find_all("a")
            if link.get("href")
        ]

    def is_mobile_friendly(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is using responsive design."""
        headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        }
        return (
            requests.get(self.url, headers=headers, timeout=timeout).status_code == 200
        )

    def has_responsive_design(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is using responsive design."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        return any(
            "viewport" in tag.get("name", "").lower() for tag in soup.find_all("meta")
        )

    def has_cookies(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is using cookies."""
        return bool(requests.get(self.url, timeout=timeout).cookies)

    def has_google_analytics(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is using Google Analytic."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        return any(
            "google-analytics.com/analytics.js" in tag.get("src", "").lower()
            for tag in soup.find_all("script")
        )

    def page_meta_description(
        self,
        /,
        *,
        timeout: int = 10,
    ) -> Optional[str | list[str] | Any]:
        """Returns the meta description for the webpage, given its URL."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        meta_description: Optional[bs4.Tag | bs4.NavigableString] = soup.find(
            "meta",
            attrs={"name": "description"},
        )
        return meta_description.get("content") if meta_description else None  # type: ignore

    def has_meta_description(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is a meta description."""
        return bool(self.page_meta_description(timeout=timeout))

    def page_keywords(self, /, *, timeout: int = 10) -> Optional[str | list[str] | Any]:
        """Returns the meta keywords for the webpage, given its URL."""
        response: requests.Response = requests.get(self.url, timeout=timeout)
        soup: bs4.BeautifulSoup = bs4.BeautifulSoup(response.text, "html.parser")
        meta_keywords: Optional[bs4.Tag | bs4.NavigableString] = soup.find(
            "meta",
            attrs={"name": "keywords"},
        )
        return meta_keywords.get("content") if meta_keywords else None  # type: ignore

    def has_keywords(self, /, *, timeout: int = 10) -> bool:
        """Checks whether the website is keywords."""
        return bool(self.page_keywords(timeout=timeout))
