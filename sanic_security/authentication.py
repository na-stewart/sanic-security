import base64
import functools
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import IntegrityError, DoesNotExist

from sanic_security.configuration import config as security_config
from sanic_security.exceptions import (
    NotFoundError,
    CredentialsError,
    SessionError,
    DeactivatedError,
)
from sanic_security.models import Account, AuthenticationSession, Role
from sanic_security.utils import get_ip

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
        CredentialsError
    """
    if not re.search(
        r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", request.form.get("email")
    ):
        raise CredentialsError("Please use a valid email such as you@mail.com.", 400)
    if not re.search(r"^[A-Za-z0-9_-]{3,32}$", request.form.get("username")):
        raise CredentialsError(
            "Username must be between 3-32 characters and not contain any special characters other than _ or -.",
            400,
        )
    if request.form.get("phone") and not re.search(
        r"^[0-9]{11,14}$", request.form.get("phone")
    ):
        raise CredentialsError(
            "Please use a valid phone format such as 15621435489 or 19498963648018.",
            400,
        )
    if 100 > len(request.form.get("password")) > 8:
        raise CredentialsError(
            "Password must be more than 8 characters and must be less than 100 characters.",
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
    except IntegrityError:
        raise CredentialsError(
            "An account with these credentials may already exist.",
            409,
        )


async def login(request: Request, account: Account = None) -> AuthenticationSession:
    """
    Login with email or username (if enabled) and password.

    Args:
        request (Request): Sanic request parameter. Login credentials are retrieved via the authorization header.
        account (Account): Account being logged into. If None, an account is retrieved via credentials in the authorization header.

    Returns:
        authentication_session

    Raises:
        CredentialsError
        NotFoundError
    """
    if request.headers.get("Authorization"):
        authorization_type, credentials = request.headers.get("Authorization").split()
        if authorization_type == "Basic":
            email_or_username, password = (
                base64.b64decode(credentials).decode().split(":")
            )
        else:
            raise CredentialsError("Invalid authorization header type.")
    else:
        raise CredentialsError("Credentials not provided.")
    if not account:
        try:
            account = await Account.get_via_email(email_or_username)
        except NotFoundError as e:
            if security_config.ALLOW_LOGIN_WITH_USERNAME:
                account = await Account.get_via_username(email_or_username)
            else:
                raise e
    try:
        password_hasher.verify(account.password, password)
        if password_hasher.check_needs_rehash(account.password):
            account.password = password_hasher.hash(password)
            await account.save(update_fields=["password"])
        account.validate()
        return await AuthenticationSession.new(request, account)
    except VerifyMismatchError:
        logger.warning(
            f"Client ({account.email}/{get_ip(request)}) login password attempt is incorrect"
        )
        raise CredentialsError("Incorrect password.", 401)


async def refresh_authentication(request: Request) -> AuthenticationSession:
    """
    Retrieve authentication session without having to ask the user to login again.

    Args:
        request (Request): Sanic request parameter.

    Raises:
        DeactivatedError
        NotFoundError
        JWTDecodeError

    Returns:
        authentication_session
    """
    decoded_raw = AuthenticationSession.decode_raw(request)
    try:
        decoded_session = (
            await AuthenticationSession.filter(
                refresh_token=decoded_raw["refresh_token"]
            )
            .prefetch_related("bearer")
            .get()
        )
        if decoded_session.active and not decoded_session.deleted:
            decoded_session.active = False
            await decoded_session.save(update_fields=["active"])
        else:
            await AuthenticationSession.filter(
                bearer=decoded_session.bearer, active=True, deleted=False
            ).update(active=False)
            logger.warning(
                f"Client ({decoded_session.bearer.email}/{get_ip(request)}) is using an invalid refresh token. "
                f"Deactivating all sessions associated to the bearer."
            )
            raise DeactivatedError()
    except DoesNotExist:
        raise NotFoundError("Session could not be found.")
    return await AuthenticationSession.new(request, decoded_session.bearer)


async def logout(request: Request) -> AuthenticationSession:
    """
    Deactivates client's authentication session and revokes access.

    Args:
        request (Request): Sanic request parameter.

    Raises:
        NotFoundError
        JWTDecodeError

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    if not authentication_session.active:
        raise SessionError("Already logged out.", 403)
    authentication_session.active = False
    await authentication_session.save(update_fields=["active"])
    return authentication_session


async def authenticate(request: Request) -> AuthenticationSession:
    """
    Authenticates client.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        authentication_session

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
    """
    authentication_session = await AuthenticationSession.decode(request)
    authentication_session.validate()
    authentication_session.bearer.validate()
    await authentication_session.check_client_location(request)
    return authentication_session


def requires_authentication():
    """
    Authenticates client.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/authenticate')
            @requires_authentication()
            async def on_authenticate(request, authentication_session):
                return text('User is authenticated!')

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await authenticate(request)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper


def create_initial_admin_account(app: Sanic) -> None:
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
                password=PasswordHasher().hash(security_config.INITIAL_ADMIN_PASSWORD),
                verified=True,
            )
            await account.roles.add(role)
            logger.info("Initial admin account created.")
