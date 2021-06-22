import json
import random
from unittest import TestCase

import httpx


class SecurityTest(TestCase):
    """
    Some live endpoints are used as a test endpoint would have the same exact functionality as the live.
    """

    def setUp(self):
        self.client = httpx.Client()
        self.email = "test@gmail.com"

    def parse_security_error(self, msg):
        return json.loads(msg)["message"]

    def test_registration(self):
        data = {"username": "test", "email": self.email, "password": "testtest"}
        register_response = self.client.post("http://127.0.0.1:8000/api/test/auth/register", data=data)
        assert register_response.status_code == 200, self.parse_security_error(register_response.text)
        code = json.loads(register_response.text)["data"]
        verify_response = self.client.post("http://127.0.0.1:8000/api/auth/verify", data={"code": code})
        assert verify_response.status_code == 200, self.parse_security_error(register_response.text)

    def test_captcha(self):
        captcha_request_response = self.client.post("http://127.0.0.1:8000/api/test/capt/request")
        assert captcha_request_response.status_code == 200, self.parse_security_error(captcha_request_response.text)
        captcha_img_response = self.client.get("http://127.0.0.1:8000/api/capt/img")
        assert captcha_img_response.status_code == 200, captcha_img_response.text
        code = json.loads(captcha_request_response.text)["data"]
        captcha_attempt_response = self.client.post("http://127.0.0.1:8000/api/test/capt/attempt", data={"code": code})
        assert captcha_attempt_response.status_code == 200, self.parse_security_error(captcha_attempt_response.text)

    def test_verification(self):
        verification_request_response = self.client.post("http://127.0.0.1:8000/api/test/verif/request", data={"email": self.email})
        assert verification_request_response.status_code == 200, verification_request_response.text
        code = json.loads(verification_request_response.text)["data"]
        verification_attempt_response = self.client.post("http://127.0.0.1:8000/api/test/verif/attempt", data={"code": code})
        assert verification_attempt_response.status_code == 200, self.parse_security_error(verification_attempt_response.text)

    def test_login_and_authorization(self):
        login_response = self.client.post("http://127.0.0.1:8000/api/test/auth/login",
                                          data={"email": self.email, "password": "testtest"})
        assert login_response.status_code == 200, self.parse_security_error(login_response.text)
        authorization_assign_response = self.client.post("http://127.0.0.1:8000/api/test/autho/assign")
        assert authorization_assign_response.status_code == 200, authorization_assign_response.text
        authorization_perms_response = self.client.post("http://127.0.0.1:8000/api/test/autho/perms")
        assert authorization_perms_response.status_code == 200, authorization_perms_response.text
        authorization_roles_response = self.client.post("http://127.0.0.1:8000/api/test/autho/roles")
        assert authorization_roles_response.status_code == 200, authorization_roles_response.text


