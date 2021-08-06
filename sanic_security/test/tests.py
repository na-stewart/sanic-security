import json
from unittest import TestCase

import httpx


class SecurityTest(TestCase):
    """
    Sanic Securty unit tests.
    """

    def test_authentication(self):
        """
        Registers a new account then attempts account verification and then logs into it.
        """
        client = httpx.Client()
        register_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "test",
                "email": "auth@test.com",
                "password": "testtest",
            },
        )
        assert register_response.status_code == 200, register_response.text
        code = json.loads(register_response.text)["data"]
        verify_response = client.post(
            "http://127.0.0.1:8000/api/auth/verify", data={"code": code}
        )
        assert verify_response.status_code == 200, verify_response.text
        login_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "auth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_two_factor_authentication(self):
        client = httpx.Client()
        account_creation_response = client.post(
            "http://127.0.0.1:8000/api/test/account/create",
            data={"email": "twofactorauth@test.com"},
        )
        assert (
            account_creation_response.status_code == 200
        ), account_creation_response.text
        two_factor_login_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/login/two-factor",
            data={"email": "twofactorauth@test.com", "password": "testtest"},
        )
        assert (
            two_factor_login_response.status_code == 200
        ), two_factor_login_response.text
        authenticate_response = client.post(
            "http://127.0.0.1:8000/api/test/auth",
        )
        assert authenticate_response.status_code == 401, authenticate_response.text
        code = json.loads(two_factor_login_response.text)["data"]
        second_factor_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/second-factor",
            data={"code": code},
        )
        assert second_factor_response.status_code == 200, second_factor_response.text

    def test_captcha(self):
        """
        Requests a captcha and image, then attempts the captcha using the captcha solution provided in the request captcha response.
        """
        client = httpx.Client()
        account_creation_response = client.post(
            "http://127.0.0.1:8000/api/test/account/create",
            data={"email": "captcha@test.com"},
        )
        assert (
            account_creation_response.status_code == 200
        ), account_creation_response.text
        login_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "captcha@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        captcha_request_response = client.post(
            "http://127.0.0.1:8000/api/test/capt/request"
        )
        assert (
            captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_img_response = client.get("http://127.0.0.1:8000/api/capt/img")
        assert captcha_img_response.status_code == 200, captcha_img_response.text
        captcha = json.loads(captcha_request_response.text)["data"]
        captcha_attempt_response = client.post(
            "http://127.0.0.1:8000/api/test/capt/attempt",
            data={"captcha": captcha},
        )
        assert (
            captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_verification(self):
        """
        Requests two-step verification, then attempts verification using the code provided in the request verification response.
        """
        client = httpx.Client()
        account_creation_response = client.post(
            "http://127.0.0.1:8000/api/test/account/create",
            data={"email": "verification@test.com"},
        )
        assert (
            account_creation_response.status_code == 200
        ), account_creation_response.text
        verification_request_response = client.post(
            "http://127.0.0.1:8000/api/test/verif/request",
            data={"email": "verification@test.com"},
        )
        assert (
            verification_request_response.status_code == 200
        ), verification_request_response.text
        code = json.loads(verification_request_response.text)["data"]
        verification_attempt_response = client.post(
            "http://127.0.0.1:8000/api/test/verif/attempt",
            data={"code": code},
        )
        assert (
            verification_attempt_response.status_code == 200
        ), verification_attempt_response.text

    def test_role_authorization(self):
        """
        Assigns roles to the test account, then attempts to authorise this account with those roles.
        """
        client = httpx.Client()
        account_creation_response = client.post(
            "http://127.0.0.1:8000/api/test/account/create",
            data={"email": "roleauth@test.com"},
        )
        assert (
            account_creation_response.status_code == 200
        ), account_creation_response.text
        login_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "roleauth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        roles_assign_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign"
        )
        assert roles_assign_response.status_code == 200, roles_assign_response.text
        role_authorization_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/permit"
        )
        assert (
            role_authorization_response.status_code == 200
        ), role_authorization_response.text

    def test_permission_authorization(self):
        """
        Assigns permissions to the test account, then attempts to authorise this account with those permissions.
        """
        client = httpx.Client()
        account_creation_response = client.post(
            "http://127.0.0.1:8000/api/test/account/create",
            data={"email": "permauth@test.com"},
        )
        assert (
            account_creation_response.status_code == 200
        ), account_creation_response.text
        login_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "permauth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        permissions_assign_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/perms/assign"
        )
        assert (
            permissions_assign_response.status_code == 200
        ), permissions_assign_response.text
        permission_authorization_response = client.post(
            "http://127.0.0.1:8000/api/test/auth/perms/permit"
        )
        assert (
            permission_authorization_response.status_code == 200
        ), permission_authorization_response.text
