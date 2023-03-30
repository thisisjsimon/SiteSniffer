# Site Sniffer in Python 🐽

The Site Sniffer project is a Python program that allows users to gather information about a website by providing its URL. The program extracts various details about the website, including the IP address, HTTP status code, SSL certificate information, domain registration details, load time, meta description, keywords, and a list of links on the page. It is intended for anyone who needs to perform website analysis, including web developers, SEO specialists, and website owners.


## Installation

Install sitesniffer with pip

```bash
  pip install sitesniffer
```

## Essential Python Libraries for Web Scraping and HTTP Requests

The requests library is used for sending HTTP requests and receiving responses. The socket, ssl, and idna libraries are used for working with IP addresses and SSL certificates. The whois library is used for querying WHOIS information for a domain. The re library is used for working with regular expressions. The time library is used for timing how long it takes to load a webpage. The BeautifulSoup library is used for parsing HTML.



## The defined functions included:

| Function Name  | Function Description |
| ------------- | ------------- |
| extract_hostname(url)  | Extracts the hostname from a URL  |
| get_ip_address(url)  | Gets the IP address of a domain  |
|get_status_code(url)|Gets the HTTP status code of a URL|
|check_website_accessibility(url)|Checks if a website is up and running|
|get_links(url)|Gets a list of URLs on a page|
|get_ssl_info(url)|Gets SSL certificate information for a domain|
|get_domain_info(url)| Gets domain information for a website |
|get_load_time(url)| Gets the load time for a website and its sub-pages |
|get_page_keywords(url)| Gets the meta keywords for a page |
|get_page_meta_description(url)| Gets the meta description for a page |
|check_mobile_friendly(url)| Checks if a website is using mobile-friendly design |
|check_responsive_design(url)| Checks if a website is using responsive design |