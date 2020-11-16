from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='amyrose',
    version='0.1.3',
    packages=['tests', 'amyrose', 'amyrose.lib', 'amyrose.core', 'examples', 'examples.core'],
    url='https://github.com/sunset-developer/Amy-Rose',
    license='GNU General Public License v3.0',
    author='sunset-developer',
    author_email='aidanstewart@sunsetdeveloper.com',
    description='A powerful yet simple async authentication and authorization library for Sanic.',
    long_description=long_description,
    long_description_content_type="text/markdown",
)
