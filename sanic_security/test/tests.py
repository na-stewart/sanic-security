import json
import os
from unittest import TestCase

import httpx

from sanic_security.configuration import Config


class RegistrationTest(TestCase):
    """
    Tests registration and login responses based off of registration conditions.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def register(
        self,
        email: str,
        disabled: bool,
        verified: bool,
        username: str = "test",
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
        registration_response = self.register("emailpass@register.com", False, True)
        assert registration_response.status_code == 200, registration_response.text

    def test_invalid_registration(self):
        """
        Registration with an intentionally invalid email, username, and phone.
        """
        invalid_email_registration_response = self.register(
            "invalidregister.com", False, True
        )
        assert (
            invalid_email_registration_response.status_code == 400
        ), invalid_email_registration_response.text
        invalid_phone_registration_response = self.register(
            "invalidnum@register.com", False, True, phone="218183186"
        )
        assert (
            invalid_phone_registration_response.status_code == 400
        ), invalid_phone_registration_response.text
        invalid_username_registration_response = self.register(
            "invaliduser@register.com", False, True, username="_inVal!d_"
        )
        assert (
            invalid_username_registration_response.status_code == 400
        ), invalid_username_registration_response.text
        too_many_characters_registration_response = self.register(
            "toolonguser@register.com",
            False,
            True,
            username="thisusernameistoolongtoberegisteredwith",
        )
        assert (
            too_many_characters_registration_response.status_code == 400
        ), too_many_characters_registration_response.text

    def test_registration_disabled(self):
        """
        Registration and login with a disabled account.
        """
        registration_response = self.register("disabled@register.com", True, True)
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
        registration_response = self.register("unverified@register.com", False, False)
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
            "unverified_disabled@register.com", True, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("unverified_disabled@register.com", "testtest"),
        )
        assert "UnverifiedError" in login_response.text, login_response.text


class LoginTest(TestCase):
    """
    Tests basic login, logout and two-factor authentication.
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

    def test_login_with_username(self):
        """
        Login with a username instead of an email and password.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "userpass@login.com", "username": "username_login_test"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("username_login_test", "testtest"),
        )
        assert login_response.status_code == 200, login_response.text

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

    def test_login_two_factor(self):
        """
        Login with an email and password and require a second factor for successful authentication.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "two_factor@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={
                "two_factor": True,
            },
            auth=("two_factor@login.com", "testtest"),
        )
        assert login_response.status_code == 200, login_response.text
        second_factor_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/second-factor",
            data={"code": json.loads(login_response.text)["data"]},
        )
        assert second_factor_response.status_code == 200, second_factor_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text

    def test_session_refresh(self):
        """
        Refresh client authentication session with a new session via the session's refresh token.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "refresh@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("refresh@login.com", "testtest"),
        )
        assert login_response.status_code == 200, login_response.text
        refresh_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/refresh"
        )
        assert refresh_response.status_code == 200, refresh_response.text
        invalid_refresh_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/refresh"
        )
        assert (
            invalid_refresh_response.status_code == 401
        ), invalid_refresh_response.text


class VerificationTest(TestCase):
    """
    Tests verification such as two-step verification and captcha.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_captcha(self):
        """
        Captcha request and attempt.
        """
        captcha_request_response = self.client.post(
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
            data={"email": "two_step@verification.com"},
        )
        two_step_verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
            data={"email": "two_step@verification.com"},
        )
        assert (
            two_step_verification_request_response.status_code == 200
        ), two_step_verification_request_response.text
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
                "username": "test",
                "email": "account@verification.com",
                "password": "testtest",
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
            data={"email": "permissions@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("permissions@authorization.com", "testtest"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={
                "name": "AuthTestRole",
                "permissions": "perm1:create,add, perm2:delete",
            },
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestRole",
                "permissions_required": "perm1:create,add, perm2:*",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestRole",
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
            data={"email": "roles@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("roles@authorization.com", "testtest"),
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
        os.environ["SANIC_SECURITY_SECRET"] = "test"
        security_config = Config()
        security_config.load_environment_variables()
        assert security_config.SECRET == "test"
