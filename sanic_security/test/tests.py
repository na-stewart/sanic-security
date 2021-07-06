import json
from unittest import TestCase

import httpx


class SecurityTest(TestCase):
    """
    Sanic Securty unit tests.
    """

    client = httpx.Client()

    def test_authentication(self):
        """
        Registers a new account test2@test.com, attempts account verification, and logs into it.
        """
        register_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "test",
                "email": "auth@test.com",
                "password": "testtest",
            },
        )
        assert register_response.status_code == 200, register_response.text
        code = json.loads(register_response.text)["data"]
        verify_response = self.client.post(
            "http://127.0.0.1:8000/api/auth/verify", data={"code": code}
        )
        assert verify_response.status_code == 200, verify_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "auth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_captcha(self):
        """
        Requests a captcha and image, then attempts the captcha using the captcha solution provided in the request captcha response.
        """
        account_creation_response = self.client.post("http://127.0.0.1:8000/api/test/account/create",
                                                     data={"email": "captcha@test.com"})
        assert account_creation_response.status_code == 200, account_creation_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "captcha@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        captcha_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/capt/request"
        )
        assert (
                captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_img_response = self.client.get(
            "http://127.0.0.1:8000/api/capt/img"
        )
        assert captcha_img_response.status_code == 200, captcha_img_response.text
        captcha = json.loads(captcha_request_response.text)["data"]
        captcha_attempt_response = self.client.post(
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
        account_creation_response = self.client.post("http://127.0.0.1:8000/api/test/account/create",
                                                     data={"email": "verification@test.com"})
        assert account_creation_response.status_code == 200, account_creation_response.text
        verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/verif/request",
            data={"email": "verification@test.com"},
        )
        assert (
                verification_request_response.status_code == 200
        ), verification_request_response.text
        code = json.loads(verification_request_response.text)["data"]
        verification_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/verif/attempt",
            data={"code": code},
        )
        assert (
                verification_attempt_response.status_code == 200
        ), verification_attempt_response.text

    def test_role_authorization(self):
        """
        Assigns roles to the test@test.com account, then attempts to authorise this account with those roles.
        """
        account_creation_response = self.client.post("http://127.0.0.1:8000/api/test/account/create",
                                                     data={"email": "roleauth@test.com"})
        assert account_creation_response.status_code == 200, account_creation_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "roleauth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        roles_assign_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign"
        )
        assert roles_assign_response.status_code == 200, roles_assign_response.text
        role_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/permit"
        )
        assert (
                role_authorization_response.status_code == 200
        ), role_authorization_response.text

    def test_permission_authorization(self):
        """
        Assigns permissions to the test@test.com account, then attempts to authorise this account with those permissions.
        """
        account_creation_response = self.client.post("http://127.0.0.1:8000/api/test/account/create",
                                                     data={"email": "permauth@test.com"})
        assert account_creation_response.status_code == 200, account_creation_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "permauth@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text
        permissions_assign_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/perms/assign"
        )
        assert (
                permissions_assign_response.status_code == 200
        ), permissions_assign_response.text
        permission_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/perms/permit"
        )
        assert (
                permission_authorization_response.status_code == 200
        ), permission_authorization_response.text

    def test_recovery(self):
        """
        Requests password recovery for a newly created account test3@test.com, then attempts to recover password using the code found in the recovery request response.
        Once the password is changed, a login attempt is made to test3@test.com with the new password.
        """
        account_creation_response = self.client.post("http://127.0.0.1:8000/api/test/account/create",
                                                     data={"email": "recovery@test.com"})
        assert account_creation_response.status_code == 200, account_creation_response.text
        recovery_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/recov/request",
            data={"email": "recovery@test.com"},
        )
        assert (
                recovery_request_response.status_code == 200
        ), recovery_request_response.text
        code = json.loads(recovery_request_response.text)["data"]
        recovery_recover_response = self.client.post(
            "http://127.0.0.1:8000/api/recov/recover",
            data={"password": "recovered", "code": code},
        )
        assert (
                recovery_recover_response.status_code == 200
        ), recovery_recover_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "test3@test.com", "password": "recovered"},
        )
        assert login_response.status_code == 200, login_response.text
