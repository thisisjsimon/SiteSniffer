# -*- coding: UTF-8 -*-
"""This module defines a custom exception class named SiteSnifferException, which is used in the sitesniffer package."""
from __future__ import annotations

__all__: list[str] = ["SiteSnifferException"]


class SiteSnifferException(Exception):
    """Custom exception for the sitesniffer package."""
