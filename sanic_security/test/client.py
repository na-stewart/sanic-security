import json
from unittest import TestCase

import httpx


# TODO This still needs work in the case that it's messy, not reliability.


class RegistrationTest(TestCase):
    def setUp(self):
        self.client = httpx.Client()

    def register(self, email: str, disabled: bool, verified: bool):
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "email": email,
                "disabled": disabled,
                "verified": verified,
            },
        )
        return registration_response

    def test_registration_disabled(self):
        registration_response = self.register("disabled@register.com", True, True)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "disabled@register.com"},
        )
        assert "DisabledError" in login_response.text, login_response.text

    def test_registration_unverified(self):
        registration_response = self.register("unverified@register.com", False, False)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "unverified@register.com"},
        )
        assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_unverified_disabled(self):
        registration_response = self.register(
            "unverified&disabled@register.com", True, False
        )
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "unverified&disabled@register.com"},
        )
        assert "UnverifiedError" in login_response.text, login_response.text

    def test_registration_incorrect_email(self):
        invalid_email_registration_response_1 = self.register(
            "invalid1@registercom", False, True
        )
        assert (
            invalid_email_registration_response_1.status_code == 400
        ), invalid_email_registration_response_1.text
        invalid_email_registration_response_2 = self.register(
            "invalid2 @register.com", False, True
        )
        assert (
            invalid_email_registration_response_2.status_code == 400
        ), invalid_email_registration_response_2.text


class LoginTest(TestCase):
    def setUp(self):
        self.client = httpx.Client()

    def test_login(self):
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "emailpass@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "emailpass@login.com"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_login_two_factor(self):
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "twofactor@login.com"},
        )
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/two-factor",
            data={"email": "twofactor@login.com"},
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
            "http://127.0.0.1:8000/api/test/capt",
            data={"captcha": json.loads(captcha_request_response.text)["data"]},
        )
        assert (
            captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_two_step_verification(self):
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
        registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "email": "unverified@verification.com",
                "disabled": False,
                "verified": False,
            },
        )
        assert registration_response.status_code == 200, registration_response.text
        unverified_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/unverified",
            data={"email": "unverified@verification.com"},
        )
        assert (
            unverified_login_response.status_code == 200
        ), unverified_login_response.text
        verify_account_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/verify",
            data={"code": json.loads(registration_response.text)["data"]},
        )
        assert verify_account_response.status_code == 200, verify_account_response.text
        verified_login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login/unverified",
            data={"email": "unverified@verification.com"},
        )
        assert verified_login_response.status_code == 200, verified_login_response.text
