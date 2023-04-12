#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""SiteSniffer - A tool to extract various information from a given URL

This module provides a SiteSniffer class that can extract various pieces of information from a given URL. 
The class can extract the protocol, hostname, path, IP address, domain information, HTTP status code, SSL certificate information, page load time, and URLs on a page.
"""
from __future__ import annotations

__all__: list[str] = ["SiteSniffer"]
__version__: str = "0.4"
__author__: str = "Jonah Simon"
__email__ = "thisisjsimon.github@gmail.com"
__title__: str = "sitesniffer"
__license__: str = "MIT"
__copyright__: str = "Copyright (c) 2023 thisisjsimon"

from ._sitesniffer import SiteSniffer
