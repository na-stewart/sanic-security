from unittest import IsolatedAsyncioTestCase

import pytest
from sanic import Sanic
from sanic_testing import TestManager

from sanic_security.authentication import register, login
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.utils import json


@pytest.fixture
def app():
    test_app = Sanic(__name__)
    TestManager(test_app)

    @test_app.post("register")
    async def on_register(request):
        """
        Register an account with an email, username, and password. Once the account is created successfully, a two-step session is requested and the code is emailed.
        """
        account = await register(request, verified=True)
        response = json("Registration successful!", account.json())
        return response

    @test_app.post("login")
    async def on_login(self, request):
        """
        Login with an email and password.
        """
        authentication_session = await login(request)
        response = json("Login successful!", authentication_session.account.json())
        authentication_session.encode(response, secure=False)
        return response

    initialize_security_orm(test_app)
    return test_app


def test_basic_test_client(app):
    request, response = app.test_client.post("/")

    assert response.body == b"foo"
    assert response.status == 200
