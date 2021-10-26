import functools
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.exceptions import (
    AccountError,
    SessionError,
)
from sanic_security.models import Account, SessionFactory, AuthenticationSession
from sanic_security.utils import get_ip

"""
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
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

session_factory = SessionFactory()
password_hasher = PasswordHasher()


async def register(
    request: Request, verified: bool = False, disabled: bool = False
) -> Account:
    """
    Registers a new account.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, username, password, phone (including country code).
        verified (bool): Enables or disabled the verification requirement for the account being registered.
        disabled (bool): Renders an account unusable until manually set to false if designated true.

    Returns:
        account

    Raises:
        AccountError
    """
    if not re.search(
        r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", request.form.get("email")
    ):
        raise AccountError("Please use a valid email such as you@mail.com.", 400)
    if not re.search(r"^[A-Za-z0-9_-]{3,32}$", request.form.get("username")):
        raise AccountError(
            "Username must be between 3-32 characters and not contain any special characters other than _ or -.",
            400,
        )
    if request.form.get("phone") and not re.search(
        r"^[0-9]{11,14}$", request.form.get("phone")
    ):
        raise AccountError(
            "Please use a valid phone format such as 15621435489 or 19498963648018.",
            400,
        )
    try:
        account = await Account.create(
            email=request.form.get("email").lower(),
            username=request.form.get("username"),
            password=password_hasher.hash(request.form.get("password")),
            phone=request.form.get("phone"),
            verified=verified,
            disabled=disabled,
        )
        return account
    except IntegrityError as ie:
        if ie.args[0].args[0] == 1062:
            raise AccountError("This account already exists.", 409)
        else:
            raise ie
    except ValidationError as ve:
        if "Length of" in ve.args[0]:
            raise AccountError(
                "One or more of your account registration values has too many characters.",
                400,
            )
        else:
            raise ve


async def login(
    request: Request, account: Account = None, two_factor=False
) -> AuthenticationSession:
    """
    Login with email and password. Authentication session expires after 30 days.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, password.
        account (Account): Account being logged into. If None, an account is retrieved via email in the request form-data.
        two_factor (bool): Enables or disables second factor requirement for the account's authentication session.

    Returns:
        authentication_session

    Raises:
        AccountError
    """
    if not account:
        account = await Account.get_via_email(request.form.get("email"))
    try:
        password_hasher.verify(account.password, request.form.get("password"))
        if password_hasher.check_needs_rehash(account.password):
            account.password = password_hasher.hash(request.form.get("password"))
            await account.save(update_fields=["password"])
        account.validate()
        return await session_factory.get(
            "authentication", request, account, two_factor=two_factor
        )
    except VerifyMismatchError:
        logger.warning(
            f"Client ({account.email}/{get_ip(request)}) login password attempt is incorrect"
        )
        raise AccountError("Incorrect password.", 401)


async def on_second_factor(request: Request) -> AuthenticationSession:
    """
    Removes the two-factor requirement from the client authentication session. To be used with some form of verification as the second factor.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    authentication_session.two_factor = False
    await authentication_session.save(update_fields=["two_factor"])
    return authentication_session


async def logout(authentication_session: AuthenticationSession):
    """
    Invalidates client's authentication session and revokes access.

    Args:
        authentication_session (AuthenticationSession): Authentication session being invalidated and logged out from.
    """
    authentication_session.valid = False
    await authentication_session.save(update_fields=["valid"])


async def authenticate(request: Request) -> AuthenticationSession:
    """
    Used to determine if the client is authenticated.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    authentication_session = await AuthenticationSession.decode(request)
    authentication_session.validate()
    authentication_session.account.validate()
    if authentication_session.two_factor:
        raise SessionError("A second factor is required for this session.", 401)
    await authentication_session.crosscheck_location(request)
    return authentication_session


def requires_authentication():
    """
    Used to determine if the client is authenticated.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/authenticate')
            @requires_authentication()
            async def on_authenticate(request, authentication_session):
                return text('User is authenticated!')

    Raises:
        AccountError
        SessionError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await authenticate(request)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper
