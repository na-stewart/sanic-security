import json
import os
from unittest import TestCase

import httpx

from sanic_security.configuration import Config

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


class RegistrationTest(TestCase):
    """Registration tests."""

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
                "password": "Pas$word1",
                "disabled": disabled,
                "verified": verified,
                "phone": phone,
            },
        )
        return registration_response

    def test_registration(self):
        """Account registration and login."""
        registration_response = self.register(
            "account_registration@register.test",
            "account_registration",
            False,
            True,
            "6172818371",
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("account_registration@register.test", "Pas$word1"),
        )
        assert login_response.status_code == 200, login_response.text

    def test_invalid_registration(self):
        """Registration with an intentionally invalid email, username, and phone."""
        invalid_email_registration_response = self.register(
            "invalid_register.test", "invalid_register", False, True
        )
        assert (
            invalid_email_registration_response.status_code == 400
        ), invalid_email_registration_response.text
        invalid_phone_registration_response = self.register(
            "invalidnum@register.test", "invalid_num", False, True, phone="617261746"
        )
        assert (
            invalid_phone_registration_response.status_code == 400
        ), invalid_phone_registration_response.text
        too_many_characters_registration_response = self.register(
            "too_long_user@register.test",
            "this_username_is_too_long_to_be_registered_with",
            False,
            True,
        )
        assert (
            too_many_characters_registration_response.status_code == 400
        ), too_many_characters_registration_response.text

    def test_registration_disabled(self):
        """Registration and login with a disabled account."""
        registration_response = self.register(
            "disabled@register.test", "disabled", True, True
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("disabled@register.test", "Pas$word1"),
        )
        assert "DisabledError" in login_response.text, login_response.text

    def test_registration_unverified(self):
        """Registration and login with an unverified account."""
        registration_response = self.register(
            "unverified@register.test", "unverified", False, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unverified@register.test", "Pas$word1"),
        )
        assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_unverified_disabled(self):
        """Registration and login with an unverified and disabled account."""
        registration_response = self.register(
            "unverified_disabled@register.test", "unverified_disabled", True, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unverified_disabled@register.test", "Pas$word1"),
        )
        assert "UnverifiedError" in login_response.text, login_response.text


class LoginTest(TestCase):
    """Login tests."""

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_login(self):
        """Login with an email and password."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "email_pass@login.test", "username": "email_pass"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("email_pass@login.test", "password"),
        )
        assert login_response.status_code == 200, login_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text

    def test_login_with_username(self):
        """Login with a username instead of an email and password."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "user_pass@login.test", "username": "user_pass"},
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
        """Login with an intentionally incorrect password and into a non-existent account."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "incorrect_pass@login.test", "username": "incorrect_pass"},
        )
        incorrect_password_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("incorrect_pass@login.test", "incorrect_password"),
        )
        assert (
            incorrect_password_login_response.status_code == 401
        ), incorrect_password_login_response.text
        unavailable_account_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unavailable@login.test", "password"),
        )
        assert (
            unavailable_account_login_response.status_code == 404
        ), unavailable_account_login_response

    def test_logout(self):
        """Logout of logged in account and attempt to authenticate."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "logout@login.test", "username": "logout"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("logout@login.test", "password"),
        )
        logout_response = self.client.post("http://127.0.0.1:8000/api/test/auth/logout")
        assert logout_response.status_code == 200, logout_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 401, authenticate_response.text

    def test_initial_admin_login(self):
        """Initial admin account login and authorization."""
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("admin@login.test", "admin123"),
        )
        assert login_response.status_code == 200, login_response.text
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "Root",
                "permissions_required": ["perm1:create,add", "perm2:*"],
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text

    def test_two_factor_login(self):
        """Test login with two-factor authentication requirement."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "two-factor@login.test", "username": "two-factor"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login?two-factor-authentication=true",
            auth=("two-factor@login.test", "password"),
        )
        assert login_response.status_code == 200, login_response.text
        authentication_invalid_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert (
            authentication_invalid_response.status_code == 401
        ), authentication_invalid_response.text
        two_factor_authentication_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/validate-2fa",
            data={"code": json.loads(login_response.text)["data"]},
        )
        assert (
            two_factor_authentication_attempt_response.status_code == 200
        ), two_factor_authentication_attempt_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text

    def test_anonymous_login(self):
        """Test login of anonymous user."""
        anon_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/anon"
        )
        assert anon_login_response.status_code == 200, anon_login_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text
        logout_response = self.client.post("http://127.0.0.1:8000/api/test/auth/logout")
        assert logout_response.status_code == 200, logout_response.text


class VerificationTest(TestCase):
    """Two-step verification and captcha tests."""

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_captcha(self):
        """Captcha request and attempt."""
        captcha_request_response = self.client.get(
            "http://127.0.0.1:8000/api/test/capt/request"
        )
        assert (
            captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_image_response = self.client.get(
            "http://127.0.0.1:8000/api/test/capt/image"
        )
        assert captcha_image_response.status_code == 200, captcha_image_response.text
        captcha_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/capt",
            data={"captcha": json.loads(captcha_request_response.text)["data"]},
        )
        assert (
            captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_two_step_verification(self):
        """Two-step verification request and attempt."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "two_step@verification.test", "username": "two_step"},
        )
        two_step_verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
            data={"email": "two_step@verification.test"},
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
        two_step_verification_no_email_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
        )
        assert (
            two_step_verification_no_email_request_response.status_code == 200
        ), two_step_verification_no_email_request_response.text
        two_step_verification_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step",
            data={
                "code": json.loads(
                    two_step_verification_no_email_request_response.text
                )["data"]
            },
        )
        assert (
            two_step_verification_attempt_response.status_code == 200
        ), two_step_verification_attempt_response.text

    def test_account_verification(self):
        """Account registration and verification process with successful login."""
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "account_verification",
                "email": "account_verification@verification.test",
                "password": "Pa$sword1",
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
    """Role and permissions based authorization tests."""

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_permissions_authorization(self):
        """Authorization with permissions."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "permissions@authorization.test", "username": "permissions"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("permissions@authorization.test", "password"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={
                "name": "AuthTestPerms",
                "permissions": "perm1:create,update, perm2:delete,retrieve, perm3:*",
            },
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:create,update, perm3:retrieve",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:retrieve, perm2:delete",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text

        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:create,retrieve",
            },
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:delete, perm2:create",
            },
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text

    def test_roles_authorization(self):
        """Authorization with roles."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "roles@authorization.test", "username": "roles"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("roles@authorization.test", "password"),
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

    def test_anonymous_authorization(self):
        """Authorization with anonymous client."""
        anon_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/anon"
        )
        assert anon_login_response.status_code == 200, anon_login_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={"role": "AuthTestPerms"},
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text


class MiscTest(TestCase):
    """Miscellaneous tests that cannot be categorized."""

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_environment_variable_load(self):
        """Config loads environment variables."""
        os.environ["SANIC_SECURITY_SECRET"] = "test-secret"
        security_config = Config()
        security_config.load_environment_variables()
        assert security_config.SECRET == "test-secret"

    def test_get_associated_sessions(self):
        """Retrieve sessions associated to logged in account."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={
                "email": "get_associated_sessions@misc.test",
                "username": "get_associated",
            },
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("get_associated_sessions@misc.test", "password"),
        )
        assert login_response.status_code == 200, login_response.text
        retrieve_associated_response = self.client.get(
            "http://127.0.0.1:8000/api/test/auth/associated"
        )
        assert (
            retrieve_associated_response.status_code == 200
        ), retrieve_associated_response.text

    def test_authentication_refresh(self):
        """Test automatic authentication refresh."""
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={
                "email": "refreshed@misc.test",
                "username": "refreshed",
            },
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("refreshed@misc.test", "password"),
        )
        assert login_response.status_code == 200, login_response.text
        expire_response = self.client.post("http://127.0.0.1:8000/api/test/auth/expire")
        assert expire_response.status_code == 200, expire_response.text
        authenticate_refresh_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert (
            authenticate_refresh_response.status_code == 200
        ), authenticate_refresh_response.text
        assert json.loads(authenticate_refresh_response.text)["data"]["refresh"] is True
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )  # Since session refresh handling is complete, it will be returned as a regular session now.
        assert authenticate_response.status_code == 200, authenticate_response.text
