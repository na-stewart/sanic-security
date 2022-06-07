import pytest

from sanic import Sanic
from sanic_testing.reusable import ReusableClient

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


@pytest.mark.usefixtures("app")
class TestLogin:
    """
    Tests login.
    """

    def test_login(self, app: Sanic):
        """
        Login with an email and password.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "emailpass@login.com"},
            )
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("emailpass@login.com", "testtest"),
            )
            assert login_response.status == 200, login_response.text
            authenticate_request, authenticate_response = _client.post(
                "/api/test/auth",
            )
            assert authenticate_response.status == 200, authenticate_response.text

    def test_login_with_username(self, app: Sanic):
        """
        Login with a username instead of an email and password.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "userpass@login.com", "username": "username_test"},
            )
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("username_test", "testtest"),
            )
            assert login_response.status == 200, login_response.text
            authenticate_request, authenticate_response = _client.post(
                "/api/test/auth",
            )
            assert authenticate_response.status == 200, authenticate_response.text

    def test_invalid_login(self, app: Sanic):
        """
        Login with an intentionally incorrect password and into a non existent account.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "incorrectpass@login.com"},
            )
            incorrect_password_login_request, incorrect_password_login_response = _client.post(
                "/api/test/auth/login",
                auth=("incorrectpass@login.com", "incorrecttest"),
            )
            assert (
                incorrect_password_login_response.status == 401
            ), incorrect_password_login_response.text
            unavailable_account_login_request, unavailable_account_login_response = _client.post(
                "/api/test/auth/login",
                auth=("unavailable@login.com", "testtest"),
            )
            assert (
                unavailable_account_login_response.status == 404
            ), unavailable_account_login_response

    def test_logout(self, app: Sanic):
        """
        Logout of logged in account and attempt to authenticate.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "logout@login.com"},
            )
            _client.post(
                "/api/test/auth/login",
                auth=("logout@login.com", "testtest"),
            )
            logout_request, logout_response = _client.post("/api/test/auth/logout")
            assert logout_response.status_code == 200, logout_response.text
            authenticate_request, authenticate_response = _client.post(
                "/api/test/auth",
            )
            assert authenticate_response.status == 401, authenticate_response.text

    def test_initial_admin_login(self, app: Sanic):
        """
        Initial admin account login and authorization.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("admin@example.com", "admin123"),
            )
            assert login_response.status_code == 200, login_response.text
            permitted_authorization_request, permitted_authorization_response = _client.post(
                "/api/test/auth/roles",
                data={
                    "role": "Head Admin",
                    "permissions_required": "perm1:create,add, perm2:*",
                },
            )
            assert (
                permitted_authorization_response.status == 200
            ), permitted_authorization_response.text
