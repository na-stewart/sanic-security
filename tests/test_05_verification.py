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
            data={"email": "two_step@verification.com"},
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
