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


class AuthorizationTest(TestCase):
    """
    Tests role and permissions based authorization.
    """

    def setUp(self):
        self.client = httpx.Client()

    def tearDown(self):
        self.client.close()

    def test_permissions_authorization(self):
        """
        Authorization with permissions.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "permissions@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("permissions@authorization.com", "testtest"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={
                "name": "AuthTestPerms",
                "permissions": "perm1:create,add, perm2:delete",
            },
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm1:create,add, perm2:*",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        prohibited_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestPerms",
                "permissions_required": "perm2:add, perm1:delete",
            },
        )
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text

    def test_roles_authorization(self):
        """
        Authorization with roles.
        """
        self.client.post(
            "http://127.0.0.1:8000/api/test/account",
            data={"email": "roles@authorization.com"},
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/login",
            auth=("roles@authorization.com", "testtest"),
        )
        self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles/assign",
            data={"name": "AuthTestRole"},
        )
        permitted_authorization_response = self.client.post(
            "http://127.0.0.1:8000/api/test/auth/roles",
            data={
                "role": "AuthTestRole",
            },
        )
        assert (
            permitted_authorization_response.status_code == 200
        ), permitted_authorization_response.text
        prohibited_authorization_response = self.client.post( "http://127.0.0.1:8000/api/test/auth/roles", data={"role": "InvalidRole"},)
        assert (
            prohibited_authorization_response.status_code == 403
        ), prohibited_authorization_response.text
