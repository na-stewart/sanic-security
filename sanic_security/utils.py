import datetime
import random
import string

from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse


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


def get_ip(request: Request) -> str:
    """
    Retrieves ip address from client request.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        ip
    """
    return request.remote_addr if request.remote_addr else request.ip


def get_code() -> str:
    """
    Generates random code to be used for verification.

    Returns:
        code
    """
    return "".join(random.choices(string.digits + string.ascii_uppercase, k=6))


def json(message: str, data, status_code: int = 200) -> HTTPResponse:
    """
    A preformatted Sanic json response.

    Args:
        message (int): Message describing data or relaying human-readable information.
        data (Any): Raw information to be used by client.
        status_code (int): HTTP response code.

    Returns:
        json
    """
    return sanic_json(
        {"message": message, "code": status_code, "data": data}, status=status_code
    )


def get_expiration_date(seconds: int) -> datetime.datetime:
    """
    Retrieves the date after which something (such as a session) is no longer valid.

    Args:
        seconds: Seconds added to current time.

    Returns:
        expiration_date
    """
    return (
        datetime.datetime.utcnow() + datetime.timedelta(seconds=seconds)
        if seconds > 0
        else None
    )


4
