import setuptools
from setuptools import setup

with open("README.md", "r") as rm:
    long_description = rm.read()

setup(
    name="sanic-security",
    version="0.10.2.1",
    packages=setuptools.find_packages(),
    url="https://github.com/sunset-developer/sanic-security",
    license="GNU General Public License v3.0",
    author="sunset-developer",
    install_requires=[
        "sanic==21.6.0",
        "tortoise-orm==0.17.5",
        "aiofiles==0.7.0",
        "pyjwt==2.1.0",
        "captcha==0.3",
        "aiosmtplib==1.1.6",
        "httpx==0.18.2"
    ],
    author_email="aidanstewart@sunsetdeveloper.com",
    description="A powerful, simple, and async security library for Sanic.",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
