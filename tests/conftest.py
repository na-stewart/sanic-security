from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

import pytest

from server import make_app as test_app

import sanic_security

import logging
import random

import uvloop
import asyncio
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


@pytest.fixture(scope="module", autouse=True)
def logger():
    logger = logging.getLogger(__name__)
    numeric_level = getattr(logging, "DEBUG", None)
    logger.setLevel(numeric_level)
    return logger


@pytest.fixture(params=["umongo", "tortoise"])
def app(request, monkeypatch, logger):

    # Use the fixture params to test all our ORM providers
    monkeypatch.setitem(sanic_security.configuration.DEFAULT_CONFIG, 'SANIC_SECURITY_ORM', request.param)
    monkeypatch.setenv('SANIC_SECURITY_ORM', request.param)

    sanic_app = test_app()
    # Hack to do some poor code work in the app for some workarounds for broken fucntions under pytest
    sanic_app.config['PYTESTING'] = True

    yield sanic_app
    sanic_app = None


@pytest.fixture(autouse=True)
def rand_phone():
    return ''.join(str(random.randint(1,9)) for i in range(10))
