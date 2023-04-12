#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
from __future__ import annotations

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as readme:
    long_description: str = readme.read()

setup(
    name="sitesniffer",
    version="0.4",
    description="This is a Python script that can extract various information about a website, including its IP address, SSL certificate information, domain information, page load time, and other useful insights.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thisisjsimon/SiteSniffer",
    author="Jonah Simon",
    author_email="thisisjsimon.github@gmail.com",
    license="MIT",
    packages=["sitesniffer"],
    package_dir={"sitesniffer": "src/sitesniffer"},
    py_modules=["exceptions", "data"],
    install_requires=["python-whois", "bs4", "idna", "requests"],
    extras_require={"dev": ["pytest", "twine"]},
    keywords=[
        "sniffing",
        "site sniffing",
        "website sniffing",
        "IP address",
        "SSL certificate",
        "domain",
        "website",
    ],
)
