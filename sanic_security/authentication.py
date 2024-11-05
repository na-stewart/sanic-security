import functools
import re
import warnings

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import DoesNotExist

from sanic_security.configuration import config as security_config, DEFAULT_CONFIG
from sanic_security.exceptions import (
    CredentialsError,
    DeactivatedError,
    SecondFactorFulfilledError,
    ExpiredError,
    AuditWarning,
)
from sanic_security.models import Account, AuthenticationSession, Role, TwoStepSession
from sanic_security.utils import get_ip

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

password_hasher = PasswordHasher()


async def register(
    request: Request, verified: bool = False, disabled: bool = False
) -> Account:
    """
    Registers a new account that can be logged into.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): email, username, password, phone (including country code).
        verified (bool): Sets the verification requirement for the account being registered.
        disabled (bool): Renders the account being registered unusable.

    Returns:
        account

    Raises:
        CredentialsError
    """
    email_lower = validate_email(request.form.get("email").lower())
    if await Account.filter(email=email_lower).exists():
        raise CredentialsError("An account with this email may already exist.", 409)
    elif await Account.filter(
        username=validate_username(request.form.get("username"))
    ).exists():
        raise CredentialsError("An account with this username may already exist.", 409)
    elif (
        request.form.get("phone")
        and await Account.filter(
            phone=validate_phone(request.form.get("phone"))
        ).exists()
    ):
        raise CredentialsError(
            "An account with this phone number may already exist.", 409
        )
    account = await Account.create(
        email=email_lower,
        username=request.form.get("username"),
        password=password_hasher.hash(validate_password(request.form.get("password"))),
        phone=request.form.get("phone"),
        verified=verified,
        disabled=disabled,
    )
    logger.info(f"Client {get_ip(request)} has registered account {account.id}.")
    return account


async def login(
    request: Request,
    account: Account = None,
    require_second_factor: bool = False,
    password: str = None,
) -> AuthenticationSession:
    """
    Login with email or username (if enabled) and password.

    Args:
        request (Request): Sanic request parameter, login credentials are retrieved via the authorization header.
        account (Account): Account being logged into, overrides account retrieved via email or username.
        require_second_factor (bool): Determines authentication session second factor requirement on login.
        password (str): Overrides user's password attempt retrieved via the authorization header.

    Returns:
        authentication_session

    Raises:
        CredentialsError
        NotFoundError
        DeletedError
        UnverifiedError
        DisabledError
    """
    if not account:
        account, password = await Account.get_via_header(request)
    elif not password:
        raise CredentialsError("Password parameter is empty.")
    try:
        password_hasher.verify(account.password, password)
        if password_hasher.check_needs_rehash(account.password):
            account.password = password_hasher.hash(password)
            await account.save(update_fields=["password"])
        account.validate()
        authentication_session = await AuthenticationSession.new(
            request, account, requires_second_factor=require_second_factor
        )
        logger.info(
            f"Client {get_ip(request)} has logged in with authentication session {authentication_session.id}."
        )
        return authentication_session
    except VerifyMismatchError:
        logger.warning(
            f"Client {get_ip(request)} has failed to log into account {account.id}."
        )
        raise CredentialsError("Incorrect password.", 401)


async def logout(request: Request) -> AuthenticationSession:
    """
    Deactivates client's authentication session.

    Args:
        request (Request): Sanic request parameter.

    Raises:
        NotFoundError
        JWTDecodeError
        DeactivatedError

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    if not authentication_session.active:
        raise DeactivatedError("Already logged out.", 403)
    authentication_session.active = False
    await authentication_session.save(update_fields=["active"])
    logger.info(
        f"Client {get_ip(request)} has logged out with authentication session {authentication_session.id}."
    )
    return authentication_session


async def fulfill_second_factor(request: Request) -> AuthenticationSession:
    """
    Fulfills client authentication session's second factor requirement via two-step session code.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): code.

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        ChallengeError
        MaxedOutChallengeError
        SecondFactorFulfilledError

    Returns:
         authentication_Session
    """
    authentication_session = await AuthenticationSession.decode(request)
    if not authentication_session.requires_second_factor:
        raise SecondFactorFulfilledError()
    two_step_session = await TwoStepSession.decode(request)
    two_step_session.validate()
    await two_step_session.check_code(request.form.get("code"))
    authentication_session.requires_second_factor = False
    await authentication_session.save(update_fields=["requires_second_factor"])
    logger.info(
        f"Client {get_ip(request)} has fulfilled authentication session {authentication_session.id} "
        "second factor."
    )
    return authentication_session


async def authenticate(request: Request) -> AuthenticationSession:
    """
    Validates client's authentication session and account. New/Refreshed session automatically returned
    if client's session expired during authentication, requires encoding.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        authentication_session

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        DeactivatedError
        UnverifiedError
        DisabledError
        SecondFactorRequiredError
        ExpiredError
    """
    authentication_session = await AuthenticationSession.decode(request)
    try:
        authentication_session.validate()
        if not authentication_session.anonymous:
            authentication_session.bearer.validate()
    except ExpiredError:
        authentication_session = await authentication_session.refresh(request)
    request.ctx.authentication_session = authentication_session
    return authentication_session


def requires_authentication(arg=None):
    """
    Validates client's authentication session and account. New/Refreshed session automatically returned
    if client's session expired during authentication, requires encoding.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/authenticate')
            @requires_authentication
            async def on_authenticate(request):
                return text('User is authenticated!')

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        DeactivatedError
        UnverifiedError
        DisabledError
        ExpiredError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            await authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator(arg) if callable(arg) else decorator


def validate_email(email: str) -> str:
    """
    Validates email format.

    Args:
        email (str): Email being validated.

    Returns:
        email

    Raises:
        CredentialsError
    """
    if not re.search(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        raise CredentialsError("Please use a valid email address.", 400)
    return email


def validate_username(username: str) -> str:
    """
    Validates username format.

    Args:
        username (str): Username being validated.

    Returns:
        username

    Raises:
        CredentialsError
    """
    if not re.search(r"^[A-Za-z0-9_-]{3,32}$", username):
        raise CredentialsError(
            "Username must be between 3-32 characters and not contain any special characters other than _ or -.",
            400,
        )
    return username


def validate_phone(phone: str) -> str:
    """
    Validates phone number format.

    Args:
        phone (str): Phone number being validated.

    Returns:
        phone

    Raises:
        CredentialsError
    """
    if phone and not re.search(
        r"^(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$", phone
    ):
        raise CredentialsError("Please use a valid phone number.", 400)
    return phone


def validate_password(password: str) -> str:
    """
    Validates password requirements.

    Args:
        password (str): Password being validated.

    Returns:
        password

    Raises:
        CredentialsError
    """
    if not re.search(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).*$", password):
        raise CredentialsError(
            "Password must contain one capital letter, one number, and one special character",
            400,
        )
    return password


def initialize_security(app: Sanic, create_root=True) -> None:
    """
    Audits configuration, creates root administrator account, and attaches refresh encoder middleware.

    Args:
        app (Sanic): The main Sanic application instance.
        create_root (bool): Determines root account creation on initialization.
    """

    @app.on_response
    async def refresh_encoder_middleware(request, response):
        if hasattr(request.ctx, "authentication_session"):
            authentication_session = request.ctx.authentication_session
            if authentication_session.is_refresh:
                authentication_session.encode(response)

    @app.listener("before_server_start")
    async def audit_configuration(app, loop):
        if security_config.SECRET == DEFAULT_CONFIG["SECRET"]:
            warnings.warn("Secret should be changed from default.", AuditWarning)
        if not security_config.SESSION_HTTPONLY:
            warnings.warn("HttpOnly should be enabled.", AuditWarning)
        if not security_config.SESSION_SECURE:
            warnings.warn("Secure should be enabled.", AuditWarning)
        if security_config.SESSION_SAMESITE.lower() == "none":
            warnings.warn("SameSite should not be set to none.", AuditWarning)
        if (
            create_root
            and security_config.INITIAL_ADMIN_EMAIL
            == DEFAULT_CONFIG["INITIAL_ADMIN_EMAIL"]
        ):
            warnings.warn(
                "Initial admin email should be changed from default.", AuditWarning
            )
        if (
            create_root
            and security_config.INITIAL_ADMIN_PASSWORD
            == DEFAULT_CONFIG["INITIAL_ADMIN_PASSWORD"]
        ):
            warnings.warn(
                "Initial admin password should be changed from default.", AuditWarning
            )

    @app.listener("before_server_start")
    async def create_root_account(app, loop):
        if not create_root:
            return
        try:
            role = await Role.filter(name="Root").get()
        except DoesNotExist:
            role = await Role.create(
                description="Has administrator abilities, assign sparingly.",
                permissions="*:*",
                name="Root",
            )
        try:
            account = await Account.filter(
                email=security_config.INITIAL_ADMIN_EMAIL
            ).get()
            await account.fetch_related("roles")
            if role not in account.roles:
                await account.roles.add(role)
                logger.warning("Initial admin account role has been reinstated.")
        except DoesNotExist:
            account = await Account.create(
                username="Root",
                email=security_config.INITIAL_ADMIN_EMAIL,
                password=password_hasher.hash(security_config.INITIAL_ADMIN_PASSWORD),
                verified=True,
            )
            await account.roles.add(role)
            logger.info("Initial admin account created.")
