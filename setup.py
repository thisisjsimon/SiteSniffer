from setuptools import find_packages, setup
import subprocess

from sitesniffer import __version__

subprocess.run("pip install -r requirements.txt", shell=True, check=True)

with open("README.md", "r") as fh:
    long_description = fh.read()



setup(
    name='sitesniffer',
    version=__version__,
    description='This is a Python script that can extract various information about a website, including its IP address, SSL certificate information, domain information, page load time, and other useful insights.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/thisisjsimon/SiteSniffer',
    author='Jonah Simon',
    author_email='thisisjsimon.github@gmail.com',
    license='MIT',
    py_modules=['sitesniffer'],
    install_requires=[
        "whois",
        "bs4",
        "idna",
        "colorama",
        "requests"
    ],
    extras_require={
        "dev": ["pytest>=7.0", "twine>=4.0.2"]
    }
)