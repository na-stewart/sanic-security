import pytest

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
class TestAuthorization:
    """
    Tests role and permissions based authorization.
    """

    def test_permissions_authorization(self, app: Sanic):
        """
        Authorization with permissions.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "permissions@authorization.com", "username": "permissions"},
            )
            _client.post(
                "/api/test/auth/login",
                auth=("permissions@authorization.com", "testtest"),
            )
            _client.post(
                "/api/test/auth/roles/assign",
                data={
                    "name": "AuthTestPerms",
                    "permissions": "perm1:create,add, perm2:delete",
                },
            )
            permitted_authorization_request, permitted_authorization_response = _client.post(
                "/api/test/auth/roles",
                data={
                    "role": "AuthTestPerms",
                    "permissions_required": "perm1:create,add, perm2:*",
                },
            )
            assert (
                permitted_authorization_response.status == 200
            ), permitted_authorization_response.text
            prohibited_authorization_request, prohibited_authorization_response = _client.post(
                "/api/test/auth/roles",
                data={
                    "role": "AuthTestPerms",
                    "permissions_required": "perm2:add, perm1:delete",
                },
            )
            assert (
                prohibited_authorization_response.status == 403
            ), prohibited_authorization_response.text

    def test_roles_authorization(self, app: Sanic):
        """
        Authorization with roles.
        """
        _client = ReusableClient(app, host='127.0.0.1', port='8000')
        with _client:
            _client.post(
                "/api/test/account",
                data={"email": "roles@authorization.com", "username": "roles"},
            )
            _client.post(
                "/api/test/auth/login",
                auth=("roles@authorization.com", "testtest"),
            )
            _client.post(
                "/api/test/auth/roles/assign",
                data={"name": "AuthTestRole"},
            )
            permitted_authorization_request, permitted_authorization_response = _client.post(
                "/api/test/auth/roles",
                data={
                    "role": "AuthTestRole",
                },
            )
            assert (
                permitted_authorization_response.status == 200
            ), permitted_authorization_response.text
            prohibited_authorization_request, prohibited_authorization_response = _client.post( "/api/test/auth/roles", data={"role": "InvalidRole"},)
            assert (
                prohibited_authorization_response.status == 403
            ), prohibited_authorization_response.text
