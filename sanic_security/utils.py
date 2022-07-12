import datetime
import random
import string

import jwt
from jwt import DecodeError

from captcha.image import ImageCaptcha
from io import BytesIO

from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse, raw
from sanic.log import logger

from sanic_security.exceptions import JWTDecodeError, NotFoundError
from sanic_security.configuration import config as security_config

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


def get_image(self) -> HTTPResponse:
    """
    Retrieves captcha image file.

    Returns:
        captcha_image
    """
    image = ImageCaptcha(190, 90)
    with BytesIO() as output:
        image.generate_image(self.code).save(output, format="JPEG")
        return raw(output.getvalue(), content_type="image/jpeg")


def encode(session, response: HTTPResponse) -> None:
    """
    Transforms session into JWT and then is stored in a cookie.

    Args:
        response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
    """
    payload = {
        "id": str(session.id),
        "date_created": str(session.date_created),
        "expiration_date": str(session.expiration_date),
        "ip": session.ip,
        **session.ctx.__dict__,
    }
    cookie = f"{security_config.SANIC_SECURITY_SESSION_PREFIX}_{session.__class__.__name__.lower()[:4]}_session"
    encoded_session = jwt.encode(
        payload, security_config.SANIC_SECURITY_SECRET, security_config.SANIC_SECURITY_SESSION_ENCODING_ALGORITHM
    )
    if isinstance(encoded_session, bytes):
        response.cookies[cookie] = encoded_session.decode()
    elif isinstance(encoded_session, str):
        response.cookies[cookie] = encoded_session
    response.cookies[cookie]["httponly"] = security_config.SANIC_SECURITY_SESSION_HTTPONLY
    response.cookies[cookie]["samesite"] = security_config.SANIC_SECURITY_SESSION_SAMESITE
    response.cookies[cookie]["secure"] = security_config.SANIC_SECURITY_SESSION_SECURE
    if security_config.SANIC_SECURITY_SESSION_EXPIRES_ON_CLIENT and session.expiration_date:
        response.cookies[cookie]["expires"] = session.expiration_date
    if security_config.SANIC_SECURITY_SESSION_DOMAIN:
        response.cookies[cookie]["domain"] = security_config.SANIC_SECURITY_SESSION_DOMAIN


def decode_raw(cls, request: Request) -> dict:
    """
    Decodes JWT token from client cookie into a python dict.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        session_dict

    Raises:
        JWTDecodeError
    """
    if isinstance(cls, type):
        cookie = request.cookies.get(
            f"{security_config.SANIC_SECURITY_SESSION_PREFIX}_{cls().__class__.__name__.lower()[:4]}_session"
        )
    else:
        cookie = request.cookies.get(
            f"{security_config.SANIC_SECURITY_SESSION_PREFIX}_{cls.__class__.__name__.lower()[:4]}_session"
        )

    try:
        if not cookie:
            raise JWTDecodeError("Session token not provided.")
        else:
            return jwt.decode(
                cookie,
                security_config.SANIC_SECURITY_SECRET
                if not security_config.SANIC_SECURITY_PUBLIC_SECRET
                else security_config.SANIC_SECURITY_PUBLIC_SECRET,
                security_config.SANIC_SECURITY_SESSION_ENCODING_ALGORITHM,
            )
    except DecodeError as e:
        raise JWTDecodeError(str(e))

#@classmethod
async def decode(cls, request: Request):
    """
    Decodes session JWT from client cookie to a Sanic Security session.

    Args:
        cls: Class of the session
        request (Request): Sanic request parameter.

    Returns:
        session

    Raises:
        JWTDecodeError
        NotFoundError
    """
    try:
        decoded_raw = decode_raw(cls, request)
        logger.debug(f'Decoded_Raw: {decoded_raw}')
        decoded_session, session_bearer = await cls.lookup(id=decoded_raw["id"])
        if not decoded_session:
            raise NotFoundError("Session could not be found.")
    except NotFoundError:
        raise NotFoundError("Session could not be found.")
    return decoded_session, session_bearer
