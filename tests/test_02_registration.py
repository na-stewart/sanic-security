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


class RegistrationTest(TestCase):
    """
    Tests registration.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def register(
        self,
        email: str,
        username: str,
        disabled: bool,
        verified: bool,
        phone: str = None,
    ):
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": username,
                "email": email,
                "password": "testtest",
                "disabled": disabled,
                "verified": verified,
                "phone": phone,
            },
        )
        return registration_response

    def test_registration(self):
        """
        Registration and login.
        """
        registration_response = self.register(
            "emailpass@register.com", "emailpass", False, True
        )
        assert registration_response.status_code == 200, registration_response.text

    def test_invalid_registration(self):
        """
        Registration with an intentionally invalid email, username, and phone.
        """
        invalid_email_registration_response = self.register(
            "invalidregister.com", "invalid", False, True
        )
        assert (
            invalid_email_registration_response.status_code == 400
        ), invalid_email_registration_response.text
        invalid_phone_registration_response = self.register(
            "invalidnum@register.com", "invalidnum", False, True, phone="218183186"
        )
        assert (
            invalid_phone_registration_response.status_code == 400
        ), invalid_phone_registration_response.text
        invalid_username_registration_response = self.register(
            "invaliduser@register.com", "_inVal!d_", False, True
        )
        assert (
            invalid_username_registration_response.status_code == 400
        ), invalid_username_registration_response.text
        too_many_characters_registration_response = self.register(
            "toolonguser@register.com",
            "thisusernameistoolongtoberegisteredwith",
            False,
            True,
        )
        assert (
            too_many_characters_registration_response.status_code == 400
        ), too_many_characters_registration_response.text

    def test_registration_disabled(self):
        """
        Registration and login with a disabled account.
        """
        registration_response = self.register(
            "disabled@register.com", "disabled", True, True
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("disabled@register.com", "testtest"),
        )
        assert "DisabledError" in login_response.text, login_response.text

    def test_registration_unverified(self):
        """
        Registration and login with an unverified account.
        """
        registration_response = self.register(
            "unverified@register.com", "unverified", False, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unverified@register.com", "testtest"),
        )
        assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_unverified_disabled(self):
        """
        Registration and login with an unverified and disabled account.
        """
        registration_response = self.register(
            "unverified_disabled@register.com", "unverified_disabled", True, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unverified_disabled@register.com", "testtest"),
        )
