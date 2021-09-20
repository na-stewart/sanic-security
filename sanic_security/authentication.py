import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.exceptions import (
    AccountError,
    SessionError,
)
from sanic_security.models import Account, SessionFactory, AuthenticationSession
from sanic_security.utils import hash_password

session_factory = SessionFactory()


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
    if not re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.form.get("email")):
        raise AccountError("Please use a valid email format such as you@mail.com.", 400)
    if request.form.get("phone") and (
        not request.form.get("phone").isdigit() or len(request.form.get("phone")) < 11
    ):
        raise AccountError(
            "Please use a valid phone format such as 15621435489 or 19498963648018.",
            400,
        )
    try:
        account = await Account.create(
            email=request.form.get("email").lower(),
            username=request.form.get("username"),
            password=hash_password(request.form.get("password")),
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
    except ValidationError:
        raise AccountError(
            "Email, username, or phone number is too long or invalid.", 400
        )


async def login(
    request: Request, account: Account = None, two_factor=False
) -> AuthenticationSession:
    """
    Used to login to accounts registered with Sanic Security.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, password.
        account (Account): Account being logged into. If None, an account is retrieved via email with the form-data argument.
        two_factor (bool): Enables or disables second factor requirement for the account's authentication session.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    if not account:
        account = await Account.get_via_email(request.form.get("email"))
        if account.password == hash_password(request.form.get("password")):
            account.validate()
            return await session_factory.get(
                "authentication", request, account, two_factor=two_factor
            )
        else:
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
    authentication_session.account.validate()
    authentication_session.validate()
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
