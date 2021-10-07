import setuptools
from setuptools import setup

"""
Copyright (C) 2021 Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

with open("README.md", "r") as rm:
    long_description = rm.read()

setup(
    name="sanic-security",
    author="sunset-developer",
    author_email="aidanstewart@sunsetdeveloper.com",
    description="An effective, simple, and async security library for Sanic.",
    url="https://github.com/sunset-developer/sanic-security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GNU General Public License v3.0",
    version="1.0.0.1",
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "tortoise-orm>=0.17.0",
        "pyjwt>=1.7.0",
        "captcha",
        "aiofiles>=0.3.0",
    ],
    platforms="any",
)
