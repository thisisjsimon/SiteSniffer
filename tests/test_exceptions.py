from __future__ import annotations

import pytest

import sitesniffer.exceptions as exceptions_mod
from sitesniffer.exceptions import SiteSnifferException


def test_exceptions_module_metadata() -> None:
    """Verify exceptions module metadata."""
    assert exceptions_mod.__all__ == ["SiteSnifferException"]


def test_sitesniffer_exception_inheritance() -> None:
    """Verify SiteSnifferException is an Exception subclass."""
    assert issubclass(SiteSnifferException, Exception)
    exc = SiteSnifferException("Test error message")
    assert isinstance(exc, Exception)
    assert str(exc) == "Test error message"


def test_sitesniffer_exception_raising() -> None:
    """Verify SiteSnifferException can be raised and caught."""
    with pytest.raises(SiteSnifferException) as exc_info:
        raise SiteSnifferException("Something failed")
    assert "Something failed" in str(exc_info.value)
