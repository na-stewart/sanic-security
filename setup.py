import setuptools
from setuptools import setup

with open("README.md", "r") as rm:
    long_description = rm.read()

setup(
    name="sanic-security",
    author="sunset-developer",
    author_email="aidanstewart@sunsetdeveloper.com",
    description="An effective, simple, and async security library for the Sanic framework.",
    url="https://github.com/sunset-developer/sanic-security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GNU Affero General Public License v3.0",
    version="1.9.5",
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "tortoise-orm>=0.17.0",
        "pyjwt>=1.7.0",
        "captcha",
        "argon2-cffi>=20.1.0",
        "sanic>=21.3.0",
    ],
    extras_require={
        "dev": [
            "httpx>=0.13.0",
            "black",
            "blacken-docs",
            "pdoc3",
            "cryptography>=3.3.1",
        ],
        "crypto": ["cryptography>=3.3.1"],
    },
    platforms="any",
)
