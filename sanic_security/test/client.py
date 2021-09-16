import json
from unittest import TestCase

import httpx


class RegistrationTest(TestCase):
    '''
    code = json.loads(register_response.text)["data"]
    verify_response = self.client.post(
        "http://127.0.0.1:8000/api/auth/verify", data={"code": code}
    )
    '''

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
                "verified": verified
            },
        )
        return registration_response

    def login(self, email: str):
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": email, "password": "testtest"},
        )
        return login_response

    def test_registration_disabled(self):
        registration_response = self.register("disabled@register.com", True, True)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.login("disabled@register.com")
        assert "disabled." in login_response.text, login_response.text

    def test_registration_unverified(self):
        registration_response = self.register("unverified@register.com", False, True)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.login("unverified@register.com")
        assert "verification." in login_response.text, login_response.text
        verify_response = self.client.post(
            "http://127.0.0.1:8000/api/auth/verify", data={"code": json.loads(registration_response.text)["data"]}
        )
        assert verify_response.status_code == 200, verify_response.text
        login_response = self.login("unverified@register.com")
        assert login_response.status_code == 200, login_response.text

    def test_registration_unverified_disabled(self):
        registration_response = self.register("unverified&disabled@register.com", True, False)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.login("unverifieddisabled@register.com")
        assert "verification." in login_response.text, login_response.text

    def test_registration_incorrect_email(self):
        registration_response = self.register("invalid@registercom", True, False)
        assert registration_response.status_code == 400, registration_response.text


class LoginTest(TestCase):

    def setUp(self):
        self.client = httpx.Client()

    def create_account(self, email: str):
        account_creation_response = self.client.post(
            "http://127.0.0.1:8000/api/account",
            data={"email": email},
        )
        return account_creation_response

    def test_login(self):
        self.create_account("simple@login.com")
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "simple@login.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_login_two_factor(self):
        self.create_account("twofactor@login.com")
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/two-factor",
            data={"email": "twofactor@login.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        second_factor_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/second_factor",
            data={"code": json.loads(login_response.text)["data"]},
        )
        assert second_factor_response.status_code == 200, second_factor_response.text
        authenticate_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 200, authenticate_response.text


class VerificationTest(TestCase):

    def setUp(self):
        self.client = httpx.Client()

    def test_captcha(self):
        captcha_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/capt/request"
        )
        assert (
                captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/capt/attempt",
            data={"captcha": json.loads(captcha_request_response.text)["data"]},
        )
        assert (
                captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_two_step_verification(self):
        self.client.post(
            "http://127.0.0.1:8000/api/account",
            data={"email": "two-step@verification.com"},
        )
        two_step_verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/request",
            data={"email": "two-step@verification.com"}
        )
        assert (
                two_step_verification_request_response.status_code == 200
        ), two_step_verification_request_response.text
        two_step_verification_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/two-step/attempt",
            data={"captcha": json.loads(two_step_verification_request_response.text)["data"]},
        )
        assert (
                two_step_verification_attempt_response.status_code == 200
        ), two_step_verification_attempt_response.text
