import setuptools
from setuptools import setup

with open("README.md", "r") as rm:
    long_description = rm.read()

setup(
    name="sanic-security",
    version="0.10.5.0",
    packages=setuptools.find_packages(),
    url="https://github.com/sunset-developer/sanic-security",
    license="GNU General Public License v3.0",
    author="sunset-developer",
    install_requires=[
        "sanic>=21.3.0",
        "tortoise-orm>=0.17.0",
        "httpx>=0.13.0",
        "pyjwt>=1.7.0",
        "aiosmtplib>=1.1.0",
        "captcha",
        "aiofiles>=0.3.0",
    ],
    author_email="aidanstewart@sunsetdeveloper.com",
    description="A powerful, simple, and async security library for Sanic.",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
