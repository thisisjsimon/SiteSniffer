from setuptools import setup
import subprocess

from sitesniffer import __version__

subprocess.run("pip install -r requirements.txt", shell=True, check=True)

setup(
    name='sitesniffer',
    version=__version__,
    description='This is a Python script that can extract various information about a website, including its IP address, SSL certificate information, domain information, page load time, and other useful insights.',
    author='Jonah Simon',
    author_email='thisisjsimon.github@gmail.com',
    url='https://github.com/thisisjsimon/SiteSniffer',


    py_modules=['sitesniffer'],
    install_requires=[
        "whois",
        "bs4",
        "idna",
        "colorama",
        "requests"
    ],
)