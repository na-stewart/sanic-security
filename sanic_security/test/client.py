import json
from unittest import TestCase

import httpx


class RegistrationTest(TestCase):
    """
    Tests registration and login responses based off of registration conditions.
    """

    def setUp(self):
        self.client = httpx.Client()

    def register(self, email: str, disabled: bool, verified: bool):
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "test",
                "email": email,
                "password": "testtest",
                "disabled": disabled,
                "verified": verified,
            },
        )
        return registration_response

    def test_registration(self):
        """
        Registration and login.
        """
        registration_response = self.register("emailpass@register.com", False, True)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "emailpass@register.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        invalid_registration_response = self.register(
            "invalid@registercom", True, False
        )
        assert (
            invalid_registration_response.status_code == 400
        ), invalid_registration_response.text

    def test_registration_disabled(self):
        """
        Registration and login with a disabled account.
        """
        registration_response = self.register("disabled@register.com", True, True)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "disabled@register.com", "password": "testtest"},
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
            data={"email": "unverified@register.com", "password": "testtest"},
        )
        assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_unverified_disabled(self):
        """
        Registration and login with an unverified and disabled account.
        """
        registration_response = self.register(
            "unverified&disabled@register.com", True, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "unverified&disabled@register.com", "password": "testtest"},
        )
        assert "UnverifiedError" in login_response.text, login_response.text


class LoginTest(TestCase):
    """
    Tests basic login, logout and two-factor authentication.
    """

    def setUp(self):
        self.client = httpx.Client()

    def test_login(self):
        """
        Login with an email and password.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "emailpass@login.com"},
        )
        invalid_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "emailpass@login.com", "password": "incorrecttest"},
        )
        assert invalid_login_response.status_code == 401, invalid_login_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "emailpass@login.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_login_with_logout(self):
        """
        Login with an email and password then logout and attempt to authenticate.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "logout@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "logout@login.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        logout_response = self.client.post("http://127.0.0.1:8000/api/test/auth/logout")
        assert logout_response.status_code == 200, login_response.text
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
            data={"email": "twofactor@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/two-factor",
            data={"email": "twofactor@login.com", "password": "testtest"},
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


class VerificationTest(TestCase):
    """
    Tests verification such as two-step verification and captcha.
    """

    def setUp(self):
        self.client = httpx.Client()

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
            data={"email": "two-step@verification.com"},
        )
        two_step_verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
            data={"email": "two-step@verification.com"},
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
        Account verification process with successful login.
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

    def test_sufficient_roles_authorization(self):
        """
        Authorization with sufficient roles.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "sufficientroles@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "sufficientroles@authorization.com", "password": "testtest"},
        )
        self.client.post("http://127.0.0.1:8000/api/test/auth/roles/assign")
        authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles"
        )
        assert authorization_response.status_code == 200, authorization_response.text

    def test_insufficient_roles_authorization(self):
        """
        Authorization with insufficient roles.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "insufficientroles@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={
                "email": "insufficientroles@authorization.com",
                "password": "testtest",
            },
        )
        authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles"
        )
        assert authorization_response.status_code == 403, authorization_response.text

    def test_sufficient_permissions_authorization(self):
        """
        Authorization with sufficient permissions.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "sufficientperms@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "sufficientperms@authorization.com", "password": "testtest"},
        )
        self.client.post("http://127.0.0.1:8000/api/test/auth/perms/assign")
        authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/perms"
        )
        assert authorization_response.status_code == 200, authorization_response.text

    def test_insufficient_permissions_authorization(self):
        """
        Authorization with sufficient permissions.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "insufficientperms@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={
                "email": "insufficientperms@authorization.com",
                "password": "testtest",
            },
        )
        authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/perms"
        )
        assert authorization_response.status_code == 403, authorization_response.text
