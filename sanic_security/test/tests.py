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
                "password": "password",
                "disabled": disabled,
                "verified": verified,
                "phone": phone,
            },
        )
        return registration_response

    def test_registration(self):
        """
        Account registration and login.
        """
        registration_response = self.register(
            "account_registration@register.com", "account_registration", False, True
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("account_registration@register.com", "password"),
        )
        assert login_response.status_code == 200, login_response.text

    def test_invalid_registration(self):
        """
        Registration with an intentionally invalid email, username, and phone.
        """
        invalid_email_registration_response = self.register(
            "invalid_register.com", "invalid_register", False, True
        )
        assert (
            invalid_email_registration_response.status_code == 400
        ), invalid_email_registration_response.text
        invalid_phone_registration_response = self.register(
            "invalidnum@register.com", "invalid_num", False, True, phone="218183186"
        )
        assert (
            invalid_phone_registration_response.status_code == 400
        ), invalid_phone_registration_response.text
        invalid_username_registration_response = self.register(
            "invalid_user@register.com", "_inVal!d_", False, True
        )
        assert (
            invalid_username_registration_response.status_code == 400
        ), invalid_username_registration_response.text
        too_many_characters_registration_response = self.register(
            "too_long_user@register.com",
            "this_username_is_too_long_to_be_registered_with",
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
            auth=("disabled@register.com", "password"),
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
            auth=("unverified@register.com", "password"),
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
            auth=("unverified_disabled@register.com", "password"),
        )
        assert "UnverifiedError" in login_response.text, login_response.text


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
            data={"email": "email_pass@login.com", "username": "email_pass"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("email_pass@login.com", "password"),
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
            data={"email": "user_pass@login.com", "username": "user_pass"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("user_pass", "password"),
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
            data={"email": "incorrect_pass@login.com", "username": "incorrect_pass"},
        )
        incorrect_password_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("incorrect_pass@login.com", "incorrect_password"),
        )
        assert (
            incorrect_password_login_response.status_code == 401
        ), incorrect_password_login_response.text
        unavailable_account_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unavailable@login.com", "password"),
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
            data={"email": "logout@login.com", "username": "logout"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("logout@login.com", "password"),
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


class VerificationTest(TestCase):
    """
    Tests two-step verification and captcha.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_captcha(self):
        """
        Captcha request and attempt.
        """
        captcha_request_response = self.client.get(
            "http://127.0.0.1:8000/api/test/capt/request"
        )
        assert (
            captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/capt",
            data={"captcha": json.loads(captcha_request_response.text)["data"]},
        )
        assert (
            captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_two_step_verification(self):
        """
        Two step verification request and attempt.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "two_step@verification.com", "username": "two_step"},
        )
        two_step_verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
            data={"email": "two_step@verification.com"},
        )
        assert (
            two_step_verification_request_response.status_code == 200
        ), two_step_verification_request_response.text
        two_step_verification_invalid_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step",
            data={"code": "123xyz"},
        )
        assert (
            two_step_verification_invalid_attempt_response.status_code == 401
        ), two_step_verification_invalid_attempt_response.text
        two_step_verification_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step",
            data={
                "code": json.loads(two_step_verification_request_response.text)["data"]
            },
        )
        assert (
            two_step_verification_attempt_response.status_code == 200
        ), two_step_verification_attempt_response.text

    def test_account_verification(self):
        """
        Account registration and verification process with successful login.
        """
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "account_verification",
                "email": "account_verification@verification.com",
                "password": "password",
                "disabled": False,
                "verified": False,
            },
        )
        assert registration_response.status_code == 200, registration_response.text
        verify_account_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/verify",
            data={"code": json.loads(registration_response.text)["data"]},
        )
        assert verify_account_response.status_code == 200, verify_account_response.text


class AuthorizationTest(TestCase):
    """
    Tests role and permissions based authorization.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_permissions_authorization(self):
        """
        Authorization with permissions.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "permissions@authorization.com", "username": "permissions"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("permissions@authorization.com", "password"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={
                "name": "AuthTestPerms",
                "permissions": "perm1:create,add, perm2:delete",
            },
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:create,add, perm2:*",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm2:add, perm1:delete",
            },
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text

    def test_roles_authorization(self):
        """
        Authorization with roles.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "roles@authorization.com", "username": "roles"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("roles@authorization.com", "password"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={"name": "AuthTestRole"},
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestRole",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={"role": "InvalidRole"},
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text


class ConfigurationTest(TestCase):
    """
    Tests configuration.
    """

    def test_environment_variable_load(self):
        """
        Config loads environment variables.
        """
        os.environ["SANIC_SECURITY_SECRET"] = "test-secret"
        security_config = Config()
        security_config.load_environment_variables()
        assert security_config.SECRET == "test-secret"
