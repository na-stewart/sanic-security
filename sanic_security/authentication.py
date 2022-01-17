import base64
import functools
import re
import traceback

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import IntegrityError

from sanic_security.configuration import config as security_config
from sanic_security.exceptions import (
    AccountError,
    SessionError,
    NotFoundError,
    CredentialsError,
)
from sanic_security.models import Account, SessionFactory, AuthenticationSession
from sanic_security.utils import get_ip

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
            "Password must have more than 8 characters and must be less than 100 characters.",
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
            "Could not register account. Please use unique account credentials.",
            400,
        )


async def login(
    request: Request, account: Account = None, two_factor: bool = False
) -> AuthenticationSession:
    """
    Login with email or username (if enabled) and password.

    Args:
        request (Request): Sanic request parameter. Login credentials are retrieved via the authorization header.
        account (Account): Account being logged into. If None, an account is retrieved via credentials in the authorization header.
        two_factor (bool): Enables or disables second factor requirement for the account's authentication session.

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
            raise CredentialsError("Invalid authorization type.")
    else:
        raise CredentialsError("Credentials not provided.")
    if not account:
        try:
            account = await Account.get_via_email(email_or_username)
        except NotFoundError:
            if security_config.ALLOW_LOGIN_WITH_USERNAME:
                account = await Account.get_via_username(email_or_username)
    try:
        password_hasher.verify(account.password, password)
        if password_hasher.check_needs_rehash(account.password):
            account.password = password_hasher.hash(password)
            await account.save(update_fields=["password"])
        account.validate()
        return await session_factory.get(
            "authentication", request, account, two_factor=two_factor
        )
    except VerifyMismatchError:
        logger.warning(
            f"Client ({account.email}/{get_ip(request)}) login password attempt is incorrect"
        )
        raise CredentialsError("Incorrect password.", 401)


async def refresh_authentication(
    request: Request, two_factor: bool = False
) -> AuthenticationSession:
    """
    Refresh expired authentication session without having to ask the user to login again.

    Args:
        request (Request): Sanic request parameter.
        two_factor: enables or disables second factor requirement for the new authentication session.

    Raises:
        DeactivatedError
        NotFoundError
        JWTDecodeError

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.redeem(request)
    return await session_factory.get(
        "authentication", request, authentication_session.bearer, two_factor=two_factor
    )


async def on_second_factor(request: Request) -> AuthenticationSession:
    """
    Removes the two-factor requirement from the client authentication session. To be used with some form of verification as the second factor.

    Args:
        request (Request): Sanic request parameter.

    Raises:
        NotFoundError
        JWTDecodeError
        SessionError

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    if not authentication_session.two_factor:
        raise SessionError("Second factor requirement already met.")
    authentication_session.two_factor = False
    await authentication_session.save(update_fields=["two_factor"])
    return authentication_session


async def logout(authentication_session: AuthenticationSession):
    """
    Deactivates client's authentication session and revokes access.

    Args:
        authentication_session (AuthenticationSession): Authentication session being deactivated and logged out from.
    """
    authentication_session.active = False
    await authentication_session.save(update_fields=["active"])


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
    if authentication_session.two_factor:
        raise SessionError("A second factor is required.", 401)
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
