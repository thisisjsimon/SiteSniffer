from __future__ import annotations

import pickle
import socket
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sitesniffer import SiteSniffer
from sitesniffer.data import DomainInfo, SSLCertInfo
from sitesniffer.exceptions import SiteSnifferException

# pylint: disable=redefined-outer-name, missing-function-docstring


# -----------------------------------------------------------------------------
# Initialization & URL Validation Tests
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "valid_url",
    [
        "https://www.example.com/example/",
        "http://example.com",
        "http://example.com/",
        "https://example.com/path/to/resource",
        "http://sub.domain.example.co.uk:8080/path?query=1&b=2#section",
        "ftp://ftp.example.org/files",
        "ftps://ftp.example.org/files/",
        "http://localhost",
        "http://localhost/",
        "http://localhost:3000/api/v1",
        "http://127.0.0.1",
        "http://127.0.0.1:8000/test",
        "https://192.168.1.1:8443/",
        "http://example.com?key=value",
        "https://example.com/#fragment",
        "https://xn--mnchen-3ya.de/",
        "https://münchen.de/",
        "https://münchen.de/path/to/page?q=1",
    ],
)
def test_valid_urls(valid_url: str) -> None:
    """Verify that all valid URL formats are accepted, including IDNs."""
    sniffer = SiteSniffer(valid_url)
    assert sniffer.url == valid_url
    assert isinstance(sniffer.url, str)


@pytest.mark.parametrize(
    "invalid_url",
    [
        "",
        "abc",
        "example.com",
        "www.example.com",
        "http://",
        "https://",
        "ftp://",
        "file:///path/to/file",
        "httpp://example.com",
        "http:///",
        "just a text string",
        "http:// invalid space .com",
        "https://example.com#fragment",  # Legacy regex requires '/' or '?' before '#'
    ],
)
def test_invalid_urls(invalid_url: str) -> None:
    """Verify that invalid URLs raise SiteSnifferException with expected message."""
    with pytest.raises(SiteSnifferException) as exc_info:
        SiteSniffer(invalid_url)
    assert f"Invalid URL: {invalid_url}" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Object Model & Dunder Methods Tests
# -----------------------------------------------------------------------------


def test_repr(sniffer: SiteSniffer, sample_url: str) -> None:
    """Verify __repr__ format."""
    expected = f"SiteSniffer(url='{sample_url}')"
    assert repr(sniffer) == expected
    assert isinstance(repr(sniffer), str)


def test_hash_and_equality(sniffer: SiteSniffer, sample_url: str) -> None:
    """Verify __hash__ and __eq__ consistency, sets, and dict keys support."""
    expected_hash = hash((SiteSniffer, sample_url))
    assert hash(sniffer) == expected_hash
    assert isinstance(hash(sniffer), int)

    sniffer_same = SiteSniffer(sample_url)
    sniffer_diff = SiteSniffer("https://another.example.com/")

    # Hash equality
    assert hash(sniffer) == hash(sniffer_same)
    assert hash(sniffer) != hash(sniffer_diff)

    # Object equality
    assert sniffer == sniffer_same
    assert sniffer != sniffer_diff
    assert (sniffer == "https://www.example.com/example/") is False
    assert (sniffer == 123) is False

    # Set membership
    s = {sniffer}
    assert sniffer_same in s
    assert sniffer_diff not in s

    # Dict keys
    d = {sniffer: "value"}
    assert d[sniffer_same] == "value"


def test_pickle_roundtrip(sniffer: SiteSniffer) -> None:
    """Verify __reduce__ supports pickling and unpickling."""
    pickled = pickle.dumps(sniffer)
    unpickled: SiteSniffer = pickle.loads(pickled)
    assert isinstance(unpickled, SiteSniffer)
    assert unpickled.url == sniffer.url
    assert hash(unpickled) == hash(sniffer)


def test_slots_and_attribute_access(sniffer: SiteSniffer) -> None:
    """Verify slots configuration and attributes."""
    assert set(SiteSniffer.__slots__) == {"_url", "__dict__"}
    assert sniffer._url == "https://www.example.com/example/"

    # Custom attributes are allowed because "__dict__" is in __slots__
    sniffer.custom_attr = "custom"  # type: ignore[attr-defined]
    assert sniffer.custom_attr == "custom"  # type: ignore[attr-defined]


# -----------------------------------------------------------------------------
# URL Parsing & Extraction Tests
# -----------------------------------------------------------------------------


def test_extract_protocol() -> None:
    """Verify extract_protocol returns exact protocol string."""
    https_sniffer = SiteSniffer("https://www.example.com/path/")
    assert https_sniffer.extract_protocol() == "https://"
    assert isinstance(https_sniffer.extract_protocol(), str)

    http_sniffer = SiteSniffer("http://www.example.com/")
    assert http_sniffer.extract_protocol() == "http://"
    assert isinstance(http_sniffer.extract_protocol(), str)

    # Legacy quirk: _URL_GROUPS only matches 'https?://' for protocol group, so ftp returns None
    ftp_sniffer = SiteSniffer("ftp://ftp.example.org/files")
    assert ftp_sniffer.extract_protocol() is None


def test_extract_hostname() -> None:
    """Verify extract_hostname returns hostname including port when present."""
    sniffer = SiteSniffer("https://www.example.com/example/")
    assert sniffer.extract_hostname() == "www.example.com"
    assert isinstance(sniffer.extract_hostname(), str)

    subdomain_sniffer = SiteSniffer("https://sub.domain.co.uk/test")
    assert subdomain_sniffer.extract_hostname() == "sub.domain.co.uk"

    port_sniffer = SiteSniffer("http://localhost:8080/api")
    assert port_sniffer.extract_hostname() == "localhost:8080"

    ip_sniffer = SiteSniffer("http://192.168.1.1:3000/")
    assert ip_sniffer.extract_hostname() == "192.168.1.1:3000"


def test_extract_path() -> None:
    """Verify extract_path returns path string or None when omitted."""
    sniffer = SiteSniffer("https://www.example.com/example/")
    assert sniffer.extract_path() == "/example/"
    assert isinstance(sniffer.extract_path(), str)

    root_sniffer = SiteSniffer("https://www.example.com/")
    assert root_sniffer.extract_path() == "/"

    deep_sniffer = SiteSniffer("https://www.example.com/a/b/c?q=1")
    assert deep_sniffer.extract_path() == "/a/b/c?q=1"

    no_path_sniffer = SiteSniffer("https://www.example.com")
    assert no_path_sniffer.extract_path() is None


def test_extract_from_pattern_failure() -> None:
    """Verify _extract_from_pattern raises SiteSnifferException on unmatched pattern."""
    sniffer = SiteSniffer("https://www.example.com/")
    # If _url is manually forced to something that doesn't match _URL_GROUPS
    sniffer._url = ""
    with pytest.raises(SiteSnifferException) as exc_info:
        sniffer._extract_from_pattern("hostname")
    assert "Unable to exctract hostname from" in str(exc_info.value)


# -----------------------------------------------------------------------------
# IP Address Resolution Tests
# -----------------------------------------------------------------------------


def test_ip_address_dual_stack(sniffer: SiteSniffer) -> None:
    """Verify ip_address resolves dual-stack IPv4 and IPv6."""
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0),
        ),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo) as mock_getaddr:
        result = sniffer.ip_address()
        mock_getaddr.assert_called_once_with(
            "www.example.com", 0, flags=socket.AI_CANONNAME,
        )
        assert isinstance(result, dict)
        assert result == {
            "ipv4": "93.184.216.34",
            "ipv6": "2606:2800:220:1:248:1893:25c8:1946",
        }
        assert isinstance(result["ipv4"], str)
        assert isinstance(result["ipv6"], str)


def test_ip_address_ipv4_only(sniffer: SiteSniffer) -> None:
    """Verify ip_address handles IPv4 only resolution."""
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        result = sniffer.ip_address()
        assert result == {"ipv4": "192.0.2.1"}
        assert "ipv6" not in result


def test_ip_address_ipv6_only(sniffer: SiteSniffer) -> None:
    """Verify ip_address handles IPv6 only resolution."""
    mock_addrinfo = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        result = sniffer.ip_address()
        assert result == {"ipv6": "2001:db8::1"}
        assert "ipv4" not in result


def test_ip_address_unrecognized_family(sniffer: SiteSniffer) -> None:
    """Verify ip_address ignores address families that are neither AF_INET nor AF_INET6."""
    mock_addrinfo = [
        (999, socket.SOCK_STREAM, 6, "", ("unrecognized_address", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        result = sniffer.ip_address()
        assert result == {}


def test_ip_address_empty(sniffer: SiteSniffer) -> None:
    """Verify ip_address returns empty dict when no address info matches."""
    with patch("socket.getaddrinfo", return_value=[]):
        result = sniffer.ip_address()
        assert result == {}


# -----------------------------------------------------------------------------
# Domain Info Tests
# -----------------------------------------------------------------------------


def test_domain_info(sniffer: SiteSniffer, sample_whois_entry: MagicMock) -> None:
    """Verify domain_info accurately transfers all 38 whois fields to DomainInfo."""
    with patch("whois.whois", return_value=sample_whois_entry) as mock_whois:
        info = sniffer.domain_info()
        mock_whois.assert_called_once_with(sniffer.url)

        assert isinstance(info, DomainInfo)
        assert len(info) == 38

        # Explicitly assert individual fields
        assert info.domain_name == "EXAMPLE.COM"
        assert info.registrar == "RESERVED-Internet Assigned Numbers Authority"
        assert info.whois_server == "whois.iana.org"
        assert info.referral_url is None
        assert info.name_servers == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
        assert info.dnssec == "signedDelegation"

        # Explicitly assert _asdict() full schema
        asdict_res = info._asdict()
        assert isinstance(asdict_res, dict)
        assert len(asdict_res) == 38
        assert asdict_res["domain_name"] == "EXAMPLE.COM"
        assert asdict_res["referral_url"] is None
        assert asdict_res["tech_name"] is None

        # Explicitly assert _asdict_without_none() schema
        filtered = info._asdict_without_none()
        assert isinstance(filtered, dict)
        assert "referral_url" not in filtered
        assert "registrant_name" not in filtered
        assert filtered["domain_name"] == "EXAMPLE.COM"
        assert filtered["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
        assert filtered["whois_server"] == "whois.iana.org"
        assert filtered["dnssec"] == "signedDelegation"


# -----------------------------------------------------------------------------
# Status Code Tests
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("code", [200, 301, 302, 400, 403, 404, 500, 503])
def test_status_code(sniffer: SiteSniffer, code: int) -> None:
    """Verify status_code returns exact integer status and propagates timeout."""
    mock_resp = MagicMock()
    mock_resp.status_code = code

    with patch("requests.get", return_value=mock_resp) as mock_get:
        result = sniffer.status_code(timeout=15)
        mock_get.assert_called_once_with(sniffer.url, timeout=15)
        assert result == code
        assert isinstance(result, int)


def test_status_code_default_timeout(sniffer: SiteSniffer) -> None:
    """Verify default timeout is 10 seconds."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp) as mock_get:
        sniffer.status_code()
        mock_get.assert_called_once_with(sniffer.url, timeout=10)


# -----------------------------------------------------------------------------
# SSL Info Tests
# -----------------------------------------------------------------------------


def test_ssl_info(sniffer: SiteSniffer, sample_ssl_cert_dict: dict[str, Any]) -> None:
    """Verify ssl_info extracts SSL certificate and maps all 10 fields."""
    mock_sock = MagicMock()
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = sample_ssl_cert_dict

    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.create_connection") as mock_conn, patch(
        "ssl.create_default_context", return_value=mock_ssl_context,
    ):
        mock_conn.return_value.__enter__.return_value = mock_sock

        cert_info = sniffer.ssl_info()

        mock_conn.assert_called_once_with(("www.example.com", 443))
        mock_ssl_context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname="www.example.com",
        )
        assert isinstance(cert_info, SSLCertInfo)
        assert len(cert_info) == 10

        assert cert_info.subject == sample_ssl_cert_dict["subject"]
        assert cert_info.issuer == sample_ssl_cert_dict["issuer"]
        assert cert_info.version == 3
        assert cert_info.serial_number == "0C1FCB184518C7E3866741236D6B73F1"
        assert cert_info.not_before == "Jan 13 00:00:00 2023 GMT"
        assert cert_info.not_after == "Feb 13 23:59:59 2024 GMT"
        assert cert_info.subject_alt_name == sample_ssl_cert_dict["subjectAltName"]
        assert cert_info.ocsp == ("http://ocsp.digicert.com",)
        assert cert_info.ca_issuers == (
            "http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt",
        )
        # Note the legacy field name mapping: crlDistributionPoints -> clr_distribution_points
        assert cert_info.clr_distribution_points == (
            "http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
            "http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl",
        )


def test_ssl_info_idn_hostname(sample_ssl_cert_dict: dict[str, Any]) -> None:
    """Verify ssl_info punycode-encodes non-ASCII internationalized domain names."""
    idn_sniffer = SiteSniffer("https://münchen.de/")
    mock_sock = MagicMock()
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = sample_ssl_cert_dict

    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.create_connection") as mock_conn, patch(
        "ssl.create_default_context", return_value=mock_ssl_context,
    ):
        mock_conn.return_value.__enter__.return_value = mock_sock
        idn_sniffer.ssl_info()

        # "münchen.de" encodes to "xn--mnchen-3ya.de" via idna.encode
        expected_hostname = "xn--mnchen-3ya.de"
        mock_conn.assert_called_once_with((expected_hostname, 443))
        mock_ssl_context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname=expected_hostname,
        )


def test_ssl_info_empty_peer_cert(sniffer: SiteSniffer) -> None:
    """Verify ssl_info raises SiteSnifferException if getpeercert() returns empty dict/None."""
    mock_sock = MagicMock()
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = None

    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.create_connection") as mock_conn, patch(
        "ssl.create_default_context", return_value=mock_ssl_context,
    ):
        mock_conn.return_value.__enter__.return_value = mock_sock
        with pytest.raises(SiteSnifferException) as exc_info:
            sniffer.ssl_info()
        assert "Unable to fetch SSL certificate information" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Page Load Time Tests
# -----------------------------------------------------------------------------


def test_load_time_with_images(sniffer: SiteSniffer, rich_html_content: str) -> None:
    """Verify load_time measures page + image fetching and rounds to ndigits."""
    page_resp = MagicMock()
    page_resp.content = rich_html_content.encode("utf-8")
    img_resp = MagicMock()

    # Requests: 1 for page + 2 for images in rich_html_content
    with patch("requests.get", side_effect=[page_resp, img_resp, img_resp]) as mock_get, patch(
        "time.perf_counter", side_effect=[100.0, 101.23456],
    ):
        load_time = sniffer.load_time(ndigits=3, timeout=5)

        assert mock_get.call_count == 3
        # Page request
        assert mock_get.call_args_list[0].args[0] == sniffer.url
        assert mock_get.call_args_list[0].kwargs["timeout"] == 5
        # Image 1 (relative URL joined with base URL)
        assert mock_get.call_args_list[1].args[0] == "https://www.example.com/images/logo.png"
        # Image 2 (absolute URL)
        assert mock_get.call_args_list[2].args[0] == "https://cdn.example.com/banner.jpg"

        assert load_time == 1.235
        assert isinstance(load_time, float)


def test_load_time_no_images(sniffer: SiteSniffer, empty_html_content: str) -> None:
    """Verify load_time with single page request when no images are present."""
    page_resp = MagicMock()
    page_resp.content = empty_html_content.encode("utf-8")

    with patch("requests.get", return_value=page_resp) as mock_get, patch(
        "time.perf_counter", side_effect=[10.0, 10.45678],
    ):
        load_time = sniffer.load_time(ndigits=2)
        mock_get.assert_called_once_with(sniffer.url, timeout=10)
        assert load_time == 0.46
        assert isinstance(load_time, float)


def test_load_time_img_without_src(sniffer: SiteSniffer) -> None:
    """Verify load_time ignores img tags that lack a src attribute."""
    html_without_src = '<html><body><img alt="No src"><img src="/valid.png"></body></html>'
    page_resp = MagicMock()
    page_resp.content = html_without_src.encode("utf-8")
    img_resp = MagicMock()

    with patch("requests.get", side_effect=[page_resp, img_resp]) as mock_get, patch(
        "time.perf_counter", side_effect=[1.0, 2.0],
    ):
        load_time = sniffer.load_time()
        assert mock_get.call_count == 2
        assert load_time == 1.0


# -----------------------------------------------------------------------------
# Links Extraction Tests
# -----------------------------------------------------------------------------


def test_links(sniffer: SiteSniffer, rich_html_content: str) -> None:
    """Verify links normalizes relative URLs and preserves absolute URLs."""
    resp = MagicMock()
    resp.text = rich_html_content

    with patch("requests.get", return_value=resp) as mock_get:
        links_list = sniffer.links(timeout=8)
        mock_get.assert_called_once_with(sniffer.url, timeout=8)

        assert isinstance(links_list, list)
        assert all(isinstance(link, str) for link in links_list)
        assert links_list == [
            "https://www.iana.org/domains/example",
            "https://www.example.com/about/",
            "https://www.example.comcontact.html",
            "https://www.example.com/example/subpage",
        ]


def test_links_empty(sniffer: SiteSniffer, empty_html_content: str) -> None:
    """Verify links returns empty list when no links are present."""
    resp = MagicMock()
    resp.text = empty_html_content

    with patch("requests.get", return_value=resp):
        assert sniffer.links() == []


# -----------------------------------------------------------------------------
# Mobile Friendly & Responsive Design Tests
# -----------------------------------------------------------------------------


def test_is_mobile_friendly_true(sniffer: SiteSniffer) -> None:
    """Verify is_mobile_friendly returns True when status is 200 with iPhone User-Agent."""
    resp = MagicMock()
    resp.status_code = 200

    with patch("requests.get", return_value=resp) as mock_get:
        result = sniffer.is_mobile_friendly(timeout=12)
        mock_get.assert_called_once_with(
            sniffer.url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) "
                    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
                ),
            },
            timeout=12,
        )
        assert result is True
        assert isinstance(result, bool)


def test_is_mobile_friendly_false(sniffer: SiteSniffer) -> None:
    """Verify is_mobile_friendly returns False when status is not 200."""
    resp = MagicMock()
    resp.status_code = 403

    with patch("requests.get", return_value=resp):
        result = sniffer.is_mobile_friendly()
        assert result is False
        assert isinstance(result, bool)


def test_has_responsive_design(sniffer: SiteSniffer, rich_html_content: str, empty_html_content: str) -> None:
    """Verify has_responsive_design detects viewport meta tag."""
    resp_positive = MagicMock()
    resp_positive.text = rich_html_content

    with patch("requests.get", return_value=resp_positive):
        assert sniffer.has_responsive_design() is True
        assert isinstance(sniffer.has_responsive_design(), bool)

    resp_negative = MagicMock()
    resp_negative.text = empty_html_content

    with patch("requests.get", return_value=resp_negative):
        assert sniffer.has_responsive_design() is False


# -----------------------------------------------------------------------------
# Cookies & Google Analytics Tests
# -----------------------------------------------------------------------------


def test_has_cookies_true(sniffer: SiteSniffer) -> None:
    """Verify has_cookies returns True when Set-Cookie header is present."""
    resp = MagicMock()
    resp.headers = {"Set-Cookie": "session_id=12345; Secure; HttpOnly"}

    with patch("requests.get", return_value=resp) as mock_get:
        result = sniffer.has_cookies(timeout=7)
        mock_get.assert_called_once_with(sniffer.url, timeout=7)
        assert result is True
        assert isinstance(result, bool)


def test_has_cookies_false(sniffer: SiteSniffer) -> None:
    """Verify has_cookies returns False when Set-Cookie header is absent."""
    resp = MagicMock()
    resp.headers = {"Content-Type": "text/html"}

    with patch("requests.get", return_value=resp):
        result = sniffer.has_cookies()
        assert result is False


def test_has_google_analytics(sniffer: SiteSniffer, rich_html_content: str, empty_html_content: str) -> None:
    """Verify has_google_analytics detects analytics.js, gtag.js, and ga.js in script tags."""
    resp_positive = MagicMock()
    resp_positive.text = rich_html_content

    with patch("requests.get", return_value=resp_positive):
        assert sniffer.has_google_analytics() is True
        assert isinstance(sniffer.has_google_analytics(), bool)

    # Test modern Google Tag Manager gtag.js script
    gtag_resp = MagicMock()
    gtag_resp.text = '<html><head><script src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script></head></html>'
    with patch("requests.get", return_value=gtag_resp):
        assert sniffer.has_google_analytics() is True

    # Test legacy ga.js script
    ga_resp = MagicMock()
    ga_resp.text = '<html><head><script src="https://ssl.google-analytics.com/ga.js"></script></head></html>'
    with patch("requests.get", return_value=ga_resp):
        assert sniffer.has_google_analytics() is True

    resp_negative = MagicMock()
    resp_negative.text = empty_html_content

    with patch("requests.get", return_value=resp_negative):
        assert sniffer.has_google_analytics() is False


# -----------------------------------------------------------------------------
# Meta Description & Keywords Tests
# -----------------------------------------------------------------------------


def test_page_meta_description_present(sniffer: SiteSniffer, rich_html_content: str) -> None:
    """Verify page_meta_description returns description string when present."""
    resp = MagicMock()
    resp.text = rich_html_content

    with patch("requests.get", return_value=resp) as mock_get:
        desc = sniffer.page_meta_description(timeout=5)
        mock_get.assert_called_once_with(sniffer.url, timeout=5)
        assert desc == "This is an example website meta description."
        assert isinstance(desc, str)
        assert sniffer.has_meta_description(timeout=5) is True


def test_page_meta_description_case_insensitive(sniffer: SiteSniffer) -> None:
    """Verify page_meta_description works with mixed-case attribute names."""
    resp = MagicMock()
    resp.text = '<html><head><meta name="Description" content="Case Insensitive Description"></head></html>'

    with patch("requests.get", return_value=resp):
        desc = sniffer.page_meta_description()
        assert desc == "Case Insensitive Description"
        assert sniffer.has_meta_description() is True


def test_page_meta_description_missing_content(sniffer: SiteSniffer) -> None:
    """Verify page_meta_description returns empty list [] when content attribute is omitted."""
    resp = MagicMock()
    resp.text = '<html><head><meta name="description"></head></html>'

    with patch("requests.get", return_value=resp):
        desc = sniffer.page_meta_description()
        assert desc == []
        assert sniffer.has_meta_description() is False


def test_page_meta_description_missing(sniffer: SiteSniffer, empty_html_content: str) -> None:
    """Verify page_meta_description returns exact empty list [] when missing (legacy behavior)."""
    resp = MagicMock()
    resp.text = empty_html_content

    with patch("requests.get", return_value=resp):
        desc = sniffer.page_meta_description()
        # Note legacy behavior: returns empty list [] instead of None
        assert desc == []
        assert isinstance(desc, list)
        assert sniffer.has_meta_description() is False


def test_page_keywords_present(sniffer: SiteSniffer, rich_html_content: str) -> None:
    """Verify page_keywords returns keywords string when present."""
    resp = MagicMock()
    resp.text = rich_html_content

    with patch("requests.get", return_value=resp) as mock_get:
        keywords = sniffer.page_keywords(timeout=5)
        mock_get.assert_called_once_with(sniffer.url, timeout=5)
        assert keywords == "example, sitesniffer, testing, python"
        assert isinstance(keywords, str)
        assert sniffer.has_keywords(timeout=5) is True


def test_page_keywords_case_insensitive(sniffer: SiteSniffer) -> None:
    """Verify page_keywords works with uppercase attribute names."""
    resp = MagicMock()
    resp.text = '<html><head><meta NAME="KEYWORDS" content="python, test, idn"></head></html>'

    with patch("requests.get", return_value=resp):
        keywords = sniffer.page_keywords()
        assert keywords == "python, test, idn"
        assert sniffer.has_keywords() is True


def test_page_keywords_missing_content(sniffer: SiteSniffer) -> None:
    """Verify page_keywords returns empty list [] when content attribute is omitted."""
    resp = MagicMock()
    resp.text = '<html><head><meta name="keywords"></head></html>'

    with patch("requests.get", return_value=resp):
        keywords = sniffer.page_keywords()
        assert keywords == []
        assert sniffer.has_keywords() is False


def test_page_keywords_missing(sniffer: SiteSniffer, empty_html_content: str) -> None:
    """Verify page_keywords returns exact empty list [] when missing (legacy behavior)."""
    resp = MagicMock()
    resp.text = empty_html_content

    with patch("requests.get", return_value=resp):
        keywords = sniffer.page_keywords()
        # Note legacy behavior: returns empty list [] instead of None
        assert keywords == []
        assert isinstance(keywords, list)
        assert sniffer.has_keywords() is False
