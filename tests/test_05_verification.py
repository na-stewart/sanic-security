import pytest
import json

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
class TestVerification:
    """
    Tests two-step verification and captcha.
    """

    def test_captcha(self, app: Sanic):
        """
        Captcha request and attempt.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            captcha_request_request, captcha_request_response = _client.get(
                "/api/test/capt/request"
            )
            assert (
                captcha_request_response.status == 200
            ), captcha_request_response.text
            captcha_request_request, captcha_attempt_response = _client.post(
                "/api/test/capt",
                data={"captcha": json.loads(captcha_request_response.text)["data"]},
            )
            assert (
                captcha_attempt_response.status == 200
            ), captcha_attempt_response.text

    def test_two_step_verification(self, app: Sanic):
        """
        Two step verification request and attempt.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "two_step@verification.com"},
            )
            two_step_verification_request_request, two_step_verification_request_response = _client.post(
                "/api/test/two-step/request",
                data={"email": "two_step@verification.com"},
            )
            assert (
                two_step_verification_request_response.status == 200
            ), two_step_verification_request_response.text
            two_step_verification_invalid_attempt_request, two_step_verification_invalid_attempt_response = _client.post(
                "/api/test/two-step",
                data={"code": "123xyz"},
            )
            assert (
                two_step_verification_invalid_attempt_response.status == 401
            ), two_step_verification_invalid_attempt_response.text
            two_step_verification_attempt_request, two_step_verification_attempt_response = _client.post(
                "/api/test/two-step",
                data={
                    "code": json.loads(two_step_verification_request_response.text)["data"]
                },
            )
            assert (
                two_step_verification_attempt_response.status == 200
            ), two_step_verification_attempt_response.text

    def test_account_verification(self, app: Sanic):
        """
        Account registration and verification process with successful login.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            registration_request, registration_response = _client.post(
                "/api/test/auth/register",
                data={
                    "username": "account_verification",
                    "email": "account@verification.com",
                    "password": "testtest",
                    "disabled": False,
                    "verified": False,
                },
            )
            assert registration_response.status == 200, registration_response.text
            verify_account_request, verify_account_response = _client.post(
                "/api/test/auth/verify",
                data={"code": json.loads(registration_response.text)["data"]},
            )
            assert verify_account_response.status == 200, verify_account_response.text
