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

    def test_registration_disabled(self):
        disabled_registration_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/register",
            data={
                "username": "test",
                "email": "disabled@register.com",
                "password": "testtest",
                "disabled": True,
                "verified": True
            },
        )
        assert disabled_registration_response.status_code == 200, disabled_registration_response.text
        login_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            data={"email": "disabled@register.com", "password": "testtest"},
        )
        assert "disabled!" in login_response.text, disabled_registration_response.text
