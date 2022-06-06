from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), "../.."))

import json
import os
from unittest import TestCase

import httpx

from sanic_security.configuration import Config

"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2020-present Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


class LoginTest(TestCase):
    """
    Tests login.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_login(self):
        """
        Login with an email and password.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "emailpass@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("emailpass@login.com", "testtest"),
        )
        assert login_response.status_code == 200, login_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text

    def test_login_with_username(self):
        """
        Login with a username instead of an email and password.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "userpass@login.com", "username": "username_test"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("username_test", "testtest"),
        )
        assert login_response.status_code == 200, login_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text

    def test_invalid_login(self):
        """
        Login with an intentionally incorrect password and into a non existent account.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "incorrectpass@login.com"},
        )
        incorrect_password_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("incorrectpass@login.com", "incorrecttest"),
        )
        assert (
            incorrect_password_login_response.status_code == 401
        ), incorrect_password_login_response.text
        unavailable_account_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unavailable@login.com", "testtest"),
        )
        assert (
            unavailable_account_login_response.status_code == 404
        ), unavailable_account_login_response

    def test_logout(self):
        """
        Logout of logged in account and attempt to authenticate.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "logout@login.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("logout@login.com", "testtest"),
        )
        logout_response = self.client.post("http://127.0.0.1:8000/api/test/auth/logout")
        assert logout_response.status_code == 200, logout_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 401, authenticate_response.text

    def test_initial_admin_login(self):
        """
        Initial admin account login and authorization.
        """
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("admin@example.com", "admin123"),
        )
        assert login_response.status_code == 200, login_response.text
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "Head Admin",
                "permissions_required": "perm1:create,add, perm2:*",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
