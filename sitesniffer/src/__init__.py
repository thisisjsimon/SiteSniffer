# -*- coding: UTF-8 -*-
"""SiteSniffer - A tool to extract various information from a given URL

This module provides a SiteSniffer class that can extract various pieces of information from a given URL. 
The class can extract the protocol, hostname, path, IP address, domain information, HTTP status code, SSL certificate information, page load time, and URLs on a page.
"""
from __future__ import annotations

__all__: list[str] = ["SiteSniffer", "DomainInfo", "SiteSnifferException"]
__version__: str = "0.3.2"
__author__: str = "Jonah Simon"
__title__: str = "sitesniffer"
__license__: str = "MIT"
__copyright__: str = "Copyright (c) 2023 thisisjsimon\nCopyright (c) 2023 shouzy"

from ._sitesniffer import SiteSniffer
from .data import DomainInfo
from .exceptions import SiteSnifferException
