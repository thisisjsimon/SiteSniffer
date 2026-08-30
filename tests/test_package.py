from __future__ import annotations

import sitesniffer
from sitesniffer import SiteSniffer


def test_package_metadata() -> None:
    """Verify package-level metadata attributes and exports."""
    assert sitesniffer.__all__ == ["SiteSniffer"]
    assert sitesniffer.__version__ == "0.5.1"
    assert sitesniffer.__author__ == "Jonah Simon"
    assert sitesniffer.__email__ == "thisisjsimon.github@gmail.com"
    assert sitesniffer.__title__ == "sitesniffer"
    assert sitesniffer.__license__ == "MIT"
    assert sitesniffer.__copyright__ == "Copyright (c) 2023 thisisjsimon"
    assert sitesniffer.SiteSniffer is SiteSniffer


def test_package_docstring() -> None:
    """Verify module docstring presence."""
    assert sitesniffer.__doc__ is not None
    assert "SiteSniffer - A tool to extract various information from a given URL" in sitesniffer.__doc__
