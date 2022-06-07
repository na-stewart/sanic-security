from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

import pytest

from server import app as test_app

import logging

import uvloop
import asyncio
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


@pytest.fixture(scope="module", autouse=True)
def logger():
    logger = logging.getLogger(__name__)
    numeric_level = getattr(logging, "DEBUG", None)
    logger.setLevel(numeric_level)
    return logger


@pytest.fixture
def app():
    sanic_app = test_app
    # Hack to do some poor code work in the app for some workarounds for broken fucntions under pytest
    sanic_app.config['PYTESTING'] = True

    return sanic_app
