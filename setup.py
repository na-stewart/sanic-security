import setuptools
from setuptools import setup

with open("README.md", "r") as rm:
    long_description = rm.read()

with open("requirements.txt", "r") as rq:
    requirements = [r.strip() for r in rq.readlines()]

setup(
    name='sanic-security',
    version='0.9.12',
    packages=setuptools.find_packages(),
    url='https://github.com/sunset-developer/sanic-security',
    license='GNU General Public License v3.0',
    author='sunset-developer',
    author_email='aidanstewart@sunsetdeveloper.com',
    description='A powerful, simple, and async security library for Sanic.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=requirements
)
