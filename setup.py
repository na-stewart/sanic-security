import setuptools
from setuptools import setup

with open("README.md", "r") as rm:
    long_description = rm.read()

setup(
    name='sanic-security',
    version='0.9.13.4',
    packages=setuptools.find_packages(),
    url='https://github.com/sunset-developer/sanic-security',
    license='GNU General Public License v3.0',
    author='sunset-developer',
    install_requires=[
        'sanic',
        'tortoise-orm',
        'aiofiles',
        'pyjwt',
        'captcha',
        'aiosmtplib',
    ],
    author_email='aidanstewart@sunsetdeveloper.com',
    description='A powerful, simple, and async security library for Sanic.',
    long_description=long_description,
    long_description_content_type="text/markdown",
)
