import pytest
import random

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


@pytest.mark.usefixtures("app", "rand_phone")
class TestRegistration:
    """
    Tests registration.
    """

    #def rand_phone(self):
    #    return ''.join(str(random.randint(1,9)) for i in range(10))

    def register(
        self,
        client,
        email: str,
        username: str,
        disabled: bool,
        verified: bool,
        phone: str = None,
    ):
        registration_request, registration_response = client.post(
            "/api/test/auth/register",
            data={
                "email": email,
                "username": username,
                "password": "testtest",
                "disabled": disabled,
                "verified": verified,
                "phone": phone,
            },
        )
        return registration_request, registration_response

    def test_registration(self, app: Sanic, rand_phone):
        """
        Registration and login.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            registration_request, registration_response = self.register(
                _client, "emailpass1@register.com", "emailpass1", False, True, rand_phone,
            )
            assert registration_response.status == 200, registration_response.text

    def test_invalid_registration(self, app: Sanic, rand_phone):
        """
        Registration with an intentionally invalid email, username, and phone.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            invalid_email_registration_request, invalid_email_registration_response = self.register(
                _client, "invalidregister.com", "invalid", False, True, rand_phone,
            )
            assert (
                invalid_email_registration_response.status == 400
            ), invalid_email_registration_response.text
            invalid_phone_registration_request, invalid_phone_registration_response = self.register(
                _client, "invalidnum@register.com", "invalidnum", False, True, phone="218183186"
            )
            assert (
                invalid_phone_registration_response.status == 400
            ), invalid_phone_registration_response.text
            invalid_username_registration_request, invalid_username_registration_response = self.register(
                _client, "invaliduser@register.com", "_inVal!d_", False, True, rand_phone,
            )
            assert (
                invalid_username_registration_response.status == 400
            ), invalid_username_registration_response.text
            too_many_characters_registration_request, too_many_characters_registration_response = self.register(
                _client,
                "toolonguser@register.com",
                "thisusernameistoolongtoberegisteredwith",
                False,
                True,
                rand_phone,
            )
            assert (
                too_many_characters_registration_response.status == 400
            ), too_many_characters_registration_response.text
    
    def test_registration_disabled(self, app: Sanic, rand_phone):
        """
        Registration and login with a disabled account.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            registration_request, registration_response = self.register(
                _client, "disabled@register.com", "disabled", True, True, rand_phone,
            )
            assert registration_response.status == 200, registration_response.text
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("disabled@register.com", "testtest"),
            )
            assert "DisabledError" in login_response.text, login_response.text

    def test_registration_unverified(self, app: Sanic, rand_phone):
        """
        Registration and login with an unverified account.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            registration_request, registration_response = self.register(
                _client, "unverified@register.com", "unverified", False, False, rand_phone,
            )
            assert registration_response.status == 200, registration_response.text
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("unverified@register.com", "testtest"),
            )
            assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_unverified_disabled(self, app: Sanic, rand_phone):
        """
        Registration and login with an unverified and disabled account.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            registration_request, registration_response = self.register(
                _client, "unverified_disabled@register.com", "unverified_disabled", True, False, rand_phone,
            )
            assert registration_response.status == 200, registration_response.text
            login_request, login_response = _client.post(
                "/api/test/auth/login",
                auth=("unverified_disabled@register.com", "testtest"),
            )
