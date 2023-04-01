# -*- coding: UTF-8 -*-
from __future__ import annotations

from setuptools import find_packages, setup

from sitesniffer.src import __author__, __license__, __title__, __version__

with open("README.md", "r", encoding="utf-8") as f:
    long_description: str = f.read()

setup(
    name=__title__,
    version=__version__,
    description="This is a Python script that can extract various information about a website, including its IP address, SSL certificate information, domain information, page load time, and other useful insights.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thisisjsimon/SiteSniffer",
    author=__author__,
    author_email="thisisjsimon.github@gmail.com",
    license=__license__,
    packages=find_packages(),
    install_requires=["whois", "bs4", "idna", "requests"],
    extras_require={"dev": ["pytest", "twine"]},
)
