from sitesniffer.src._sitesniffer import SiteSniffer
import pytest



@pytest.fixture

def sniffer():
    return SiteSniffer("https://www.python.org/")


def test_extract_protocol(sniffer):
    assert sniffer.extract_protocol() == "https://"


def test_extract_hostname(sniffer):
    assert sniffer.extract_hostname() == "www.python.org"


def test_extract_path(sniffer):
    assert sniffer.extract_path() == "/"


#def test_ip_address(sniffer):
#    assert sniffer.ip_address() == "151.101.2.223"


def test_domain_info(sniffer):
    info = sniffer.domain_info()
    assert info.name == "python.org"
    assert info.registrar == "Gandi SAS"
    assert info.creation_date.year == 1995
    assert info.expiration_date.year == 2024


def test_status_code(sniffer):
    assert sniffer.status_code() == 200


def test_ssl_info(sniffer):
    assert sniffer.ssl_info()["subject"] == ((('commonName', 'www.python.org'),),)


def test_load_time(sniffer):
    assert sniffer.load_time() > 0


def test_links(sniffer):
    assert len(sniffer.links()) > 0


#def test_is_mobile_friendly(sniffer):
#    assert sniffer.is_mobile_friendly() == False


def test_has_responsive_design(sniffer):
    assert sniffer.has_responsive_design() == True


#def test_has_cookies(sniffer):
#    assert sniffer.has_cookies() == True


#def test_has_google_analytics(sniffer):
#   assert sniffer.has_google_analytics() == True


def test_page_meta_description(sniffer):
    assert "The official home of the Python Programming Language" in sniffer.page_meta_description()


def test_has_meta_description(sniffer):
    assert sniffer.has_meta_description() == True


#def test_page_keywords(sniffer):
#    assert "Python, programming language, documentation, community" in sniffer.page_keywords()


def test_has_keywords(sniffer):
    assert sniffer.has_keywords() == True
