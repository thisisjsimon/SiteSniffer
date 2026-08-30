# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-08-30

### Added
- **Modern Packaging (PEP 517 / PEP 621)**: Migrated package build configuration to `pyproject.toml` using `hatchling` as the build backend with dynamic versioning.
- **Python 3.10+ Compatibility**: Set Python requirement to `requires-python = ">=3.10"` and resolved Python 3.10 typing imports.
- **IDN (Internationalized Domain Names) Support**: Updated URL validation pattern to accept non-ASCII/Unicode domain names (e.g. `https://münchen.de/`) seamlessly with punycode encoding in SSL inspection.
- **Object Equality (`__eq__`)**: Implemented `__eq__` on `SiteSniffer` aligning with `__hash__` so instances with the same URL compare equal and function as expected in sets and dictionary keys.
- **Optional Dependency Groups**: Added `[project.optional-dependencies]` with `test` (`pytest`, `pytest-cov`) and `dev` (`ruff`, `mypy`, `types-requests`) groups.
- **Comprehensive Test Suite**: Added 100% branch and statement coverage pytest suite with unit tests and fixtures freezing legacy behavior and schema contracts.

### Changed
- **Updated Dependencies**:
  - Replaced legacy dummy package `bs4` with official `beautifulsoup4>=4.12.0`.
  - Updated `requests>=2.32.0` for modern SSL/TLS handling and security fixes.
  - Updated `idna>=3.7` addressing CVE-2024-26130.
  - Updated `python-whois>=0.9.4` with robust schema mapping.
- **Scraping Robustness**:
  - `page_meta_description()` and `page_keywords()` now use case-insensitive regex attribute matching (e.g. `<meta name="Description">`, `<META NAME="KEYWORDS">`).
  - `has_google_analytics()` now detects modern Google Tag Manager (`googletagmanager.com/gtag/js`) and legacy `ga.js` alongside `analytics.js`.

### Fixed
- Fixed `ImportError` on Python 3.10 caused by `from typing import Self`.
- Fixed `AttributeError` vulnerabilities in `domain_info()` by using safe attribute lookup across varying WHOIS registrar responses.
- Fixed `load_time()` handling when HTML `<img>` tags omit the `src` attribute.

### Removed
- Removed legacy `setup.py` and `requirements.txt` build files in favor of standard `pyproject.toml`.

---

## [0.4.1] - 2023-04-17

### Added
- Dual-stack IPv4 and IPv6 address resolution in `SiteSniffer.ip_address()`.

### Changed
- Refactored `DomainInfo` return structure and adjusted package version metadata.

---

## [0.4.0] - 2023-04-17

### Added
- Added `DomainInfo._asdict_without_none()` helper to filter out unpopulated `None` fields from WHOIS dictionaries.
- Added URL extraction utility methods: `extract_protocol()`, `extract_hostname()`, and `extract_path()`.
- Added cookie detection via `has_cookies()` and Google Analytics detection via `has_google_analytics()`.
- Added `python_requires=">=3.11"` metadata in packaging configuration.

### Fixed
- Fixed URL validation regex and test suite issues.
- Fixed None return value handling in scraping utilities.

---

## [0.3.2] - 2023-04-01

### Added
- Added `has_cookies()` method to `SiteSniffer` class.
- Added and updated unit tests for cookie detection.

### Fixed
- Fixed package test suite execution issues and `.gitignore` rules.

---

## [0.3.1] - 2023-04-01

### Changed
- Reorganized package directory structure and file layout.
- Updated documentation and usage examples in `README.md`.

### Fixed
- Bug fixes in URL parsing and response handling.

---

## [0.3.0] - 2023-04-01

### Added
- **Object-Oriented Architecture**: Refactored procedural script into the `SiteSniffer` class in `src/sitesniffer/_sitesniffer.py`.
- Introduced `DomainInfo` and `SSLCertInfo` `NamedTuple` data models in `src/sitesniffer/data.py`.
- Introduced custom `SiteSnifferException` in `src/sitesniffer/exceptions.py`.
- Type annotations across all modules with `from __future__ import annotations`.

### Changed
- Restructured project layout into standard `src/sitesniffer/` layout.

### Removed
- Removed `colorama` dependency and legacy procedural script functions.

---

## [0.2.1] - 2023-03-31

### Added
- Added type annotations to function parameters and return types.
- Updated documentation order and usage guide in `README.md`.

---

## [0.2.0] - 2023-03-30

### Added
- Initial PyPI package release with `setup.py` and `requirements.txt`.
- Added site sniffing and inspection helper functions:
  - `get_domain_info()`
  - `get_status_code()`
  - `get_links()`
  - `get_ssl_info()`
  - `get_load_time()`
  - `get_ip_address()`
  - `get_page_keywords()`
  - `get_page_meta_description()`
  - `get_site_info()`
  - `check_website_accessibility()`
  - `check_mobile_friendly()`
  - `check_responsive_design()`
  - `check_cookies()`
  - `check_google_analytics()`
