import os

from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse
from tortoise.exceptions import DoesNotExist

from sanic_security.authentication import password_hasher
from sanic_security.configuration import config as security_config
from sanic_security.models import Role, Account

"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2021 Aidan Stewart

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


def get_ip(request: Request) -> str:
    """
    Retrieves ip address from client request.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        ip
    """
    return request.remote_addr if request.remote_addr else request.ip


def dir_exists(path: str) -> bool:
    """
    Checks if path exists and isn't empty. Creates new path if neither of these conditions are met.

    Args:
        path (str): Path being checked.

    Returns:
        exists
    """
    try:
        os.makedirs(path)
        exists = False
    except FileExistsError:
        exists = os.listdir(path)
    return exists


def json(message: str, data, status_code: int = 200) -> HTTPResponse:
    """
    A preformatted Sanic json response.

    Args:
        message (int): Message describing data or relaying human readable information.
        data (Any): Raw information to be used by client.
        status_code (int): HTTP response code.

    Returns:
        json
    """
    return sanic_json(
        {"message": message, "code": status_code, "data": data}, status=status_code
    )


def generate_initial_admin(app: Sanic):
    """
    Creates the initial admin account that can be logged into and has complete authoritative access.

    Args:
        app (Sanic): The main Sanic application instance.
    """

    @app.listener("before_server_start")
    async def generate(app, loop):
        try:
            role = await Role.filter(name="Head Admin").get()
        except DoesNotExist:
            role = await Role.create(
                description="Has the ability to control any aspect of the API. Assign sparingly.",
                permissions="*:*",
                name="Head Admin",
            )
        try:
            account = await Account.filter(username="Head Admin").get()
            await account.fetch_related("roles")
            if role not in account.roles:
                await account.roles.add(role)
                logger.warning(
                    'The initial admin account role "Head Admin" was removed and has been reinstated.'
                )
        except DoesNotExist:
            account = await Account.create(
                username="Head Admin",
                email=security_config.INITIAL_ADMIN_EMAIL,
                password=password_hasher.hash(security_config.INITIAL_ADMIN_PASSWORD),
                verified=True,
            )
            await account.roles.add(role)
            logger.info("Initial admin account generated.")
