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
        login_response = self.login("disabled@register.com")
        assert "verification." in login_response.text, login_response.text

    def test_registration_unverified_disabled(self):
        registration_response = self.register("unverified&disabled@register.com", True, False)
        assert registration_response.status_code == 200, registration_response.text
        login_response = self.login("disabled@register.com")
        assert "verification." in login_response.text, login_response.text

    def test_registration_incorrect_email(self):
        registration_response = self.register("invalid@registercom", True, False)
        assert registration_response.status_code == 400, registration_response.text

