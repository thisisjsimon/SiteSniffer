import requests
import socket
import ssl
import idna
import whois
import re
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
from typing import List, Dict, Any, Union, Optional
init()


__version__: str = "0.2.1"


# Error codes
ERROR_INVALID_URL = "INVALID_URL"
ERROR_IP_ADDRESS_NOT_FOUND = "IP_ADDRESS_NOT_FOUND" 
ERROR_DOMAIN_INFO_NOT_FOUND = "DOMAIN_INFO_NOT_FOUND" 
ERROR_STATUS_CODE_NOT_FOUND = "STATUS_CODE_NOT_FOUND" 
ERROR_SSL_INFO_NOT_FOUND = "SSL_INFO_NOT_FOUND" 
ERROR_LOAD_TIME_NOT_FOUND = "LOAD_TIME_NOT_FOUND" 
ERROR_SITE_INFO_NOT_FOUND = "SITE_INFO_NOT_FOUND" 


# Function to extract the hostname from a URL
def extract_hostname(url: str) -> str:
    pattern = r"(?P<protocol>https?://)?(?P<hostname>[^/]+)(?P<path>/.*)?"
    match = re.match(pattern, url)
    if not match:
        raise Exception(ERROR_INVALID_URL)
    return match.group("hostname")


# Function to get the IP address of a domain
def get_ip_address(url: str) -> str:
    try:
        domain = urlparse(url).netloc
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        raise Exception(ERROR_IP_ADDRESS_NOT_FOUND)


# Function to get domain information for a website
def get_domain_info(url: str) -> Union[Dict[str, Union[str, None]], None]:
    try:
        w = whois.whois(url)
        domain_info: Dict[str, Union[str, None]] = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "last_updated": w.last_updated,
        }
        return domain_info
    except Exception as e:
        raise Exception(ERROR_DOMAIN_INFO_NOT_FOUND)


# Function to get the HTTP status code of a URL
def get_status_code(url: str) -> int:
    try:
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException as e:
        raise Exception(ERROR_STATUS_CODE_NOT_FOUND)


# Function to get SSL certificate information for a domain
def get_ssl_info(url: str) -> dict:
    hostname: str = extract_hostname(url)
    try:
        # encode hostname using Punycode if it contains non-ASCII characters
        hostname = idna.encode(hostname).decode("utf-8")
        with socket.create_connection((hostname, 443)) as sock:
            with ssl.create_default_context().wrap_socket(
                sock, server_hostname=hostname
            ) as ssl_sock:
                return ssl_sock.getpeercert()
    except Exception as e:
        raise Exception(ERROR_SSL_INFO_NOT_FOUND)
    

# Function to get the load time for a website and its sub-pages
def get_load_time(url: str) -> float:
    try:
        start_time: float = time.time()
        response: requests.Response = requests.get(url)
        soup: BeautifulSoup = BeautifulSoup(response.content, 'html.parser')
        for img in soup.find_all('img'):
            requests.get(urljoin(url, img['src']))
        end_time: float = time.time()
        return end_time - start_time
    except Exception as e:
        raise Exception(ERROR_LOAD_TIME_NOT_FOUND)
    

# Function to get the meta description for a webpage, given its URL
def get_page_meta_description(url: str) -> Optional[str]:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        meta_description = soup.find("meta", attrs={"name": "description"})
        return meta_description.get("content") if meta_description else None
    except requests.exceptions.RequestException:
        return None  


# Function to get the meta keywords for a webpage, given its URL
def get_page_keywords(url: str) -> str:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        return meta_keywords.get("content") if meta_keywords else None
    except requests.exceptions.RequestException as e:
        return None    


# Function to get a list of URLs on a page
def get_links(url: str) -> List[str]:
    links: List[str] = []
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    for link in soup.find_all("a"):
        href = link.get("href")
        if href:
            if href.startswith("http"):
                if href.startswith(url):
                    links.append(href)
            else:
                links.append(url + href)
    return links


# Function to check if a website is using responsive design
def check_mobile_friendly(url: str) -> bool:
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1'}
        response = requests.get(url, headers=headers)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


# Function to check if a website is using responsive design
def check_responsive_design(url: str) -> bool:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if 'viewport' in tag.get('name', '').lower():
                return True
        return False
    except Exception:
        return False


# Function to check if a website is using cookies
def check_cookies(url: str) -> bool:
    try:
        response = requests.get(url)
        return bool(response.cookies)
    except requests.exceptions.RequestException:
        return False


# Function to check if a website is using Google Analytic
def check_google_analytics(url: str) -> bool:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')
        for tag in script_tags:
            src = tag.get('src', '').lower()
            if 'google-analytics.com/analytics.js' in src:
                return True
        return False
    except Exception:
        return False


# Function to return all site infos
def get_site_info(url: str) -> Dict[str, Any]:
    try:
        ip_address: str = get_ip_address(url)
        domain_info: Dict[str, Any] = get_domain_info(url)
        server: int = get_status_code(url)
        ssl_info: Dict[str, Any] = get_ssl_info(url)
        load_time: float = get_load_time(url)
        meta_description: str = get_page_meta_description(url)
        keywords: List[str] = get_page_keywords(url)
        links: List[str] = get_links(url)
        mobile_friendly: bool = check_mobile_friendly(url)
        responsive_design: bool = check_responsive_design(url)
        has_cookies: bool = check_cookies(url)
        has_google_analytics: bool = check_google_analytics(url)
        return {
            'url': url,
            'ip_address': ip_address,
            'domain_info': domain_info,
            'server': server,
            'ssl_info': ssl_info,
            'load_time': load_time,
            'meta_description': meta_description,
            'keywords': keywords,
            'links' : links,
            'mobile_friendly': mobile_friendly,
            'responsive_design': responsive_design,
            'has_cookies': has_cookies,
            'has_google_analytics': has_google_analytics,
        }
    except Exception as e:
        raise Exception(ERROR_SITE_INFO_NOT_FOUND)


