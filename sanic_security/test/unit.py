import json
import random
from unittest import TestCase

import httpx


class SecurityTest(TestCase):
    client = httpx.Client()

    def test_authentication(self):
        email = f"{''.join(random.choices('abc', k=5))}@gmail.com"
        #Register.
        data = {"username": "test", "email": email, "password": "testtest"}
        register_response = self.client.post("http://0.0.0.0:8000/api/test/auth/register", data=data)
        assert register_response.status_code == 200
        #Verify.
        code = json.loads(register_response.read())["data"]
        verify_response = self.client.post("http://0.0.0.0:8000/api/test/auth/verify", data={"code": code})
        assert verify_response.status_code == 200
        # Login.
        login_response = self.client.post("http://0.0.0.0:8000/api/test/auth/login", data={"email": email, "password": "testtest"})
        assert login_response.status_code == 200

