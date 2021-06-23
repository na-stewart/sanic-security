import json
from unittest import TestCase

import httpx


class SecurityTest(TestCase):
    client = httpx.Client()
    client.post("http://127.0.0.1:8000/api/test/auth/setup")
    client.post(
        "http://127.0.0.1:8000/api/test/auth/login",
        data={"email": "test@test.com", "password": "testtest"},
    )

    def test_authentication(self):
        register_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "test",
                "email": "test2@test.com",
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
            data={"email": "test2@test.com", "password": "testtest"},
        )
        assert login_response.status_code == 200, login_response.text

    def test_captcha(self):
        captcha_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/captcha/request"
        )
        assert (
            captcha_request_response.status_code == 200
        ), captcha_request_response.text
        captcha_img_response = self.client.get(
            "http://127.0.0.1:8000/api/auth/captcha/img"
        )
        assert captcha_img_response.status_code == 200, captcha_img_response.text
        captcha = json.loads(captcha_request_response.text)["data"]
        captcha_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/captcha/attempt",
            data={"captcha": captcha},
        )
        assert (
            captcha_attempt_response.status_code == 200
        ), captcha_attempt_response.text

    def test_verification(self):
        verification_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/verification/request",
            data={"email": "test@test.com"},
        )
        assert (
            verification_request_response.status_code == 200
        ), verification_request_response.text
        code = json.loads(verification_request_response.text)["data"]
        verification_attempt_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/verification/attempt",
            data={"code": code},
        )
        assert (
            verification_attempt_response.status_code == 200
        ), verification_attempt_response.text

    def test_role_authorization(self):
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
        recovery_request_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/recovery/request",
            data={"email": "test3@test.com"},
        )
        assert (
            recovery_request_response.status_code == 200
        ), recovery_request_response.text
        code = json.loads(recovery_request_response.text)["data"]
        recovery_recover_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/recovery/recover",
            data={"password": "recovered", "code": code},
        )
        assert recovery_recover_response, recovery_recover_response.text
