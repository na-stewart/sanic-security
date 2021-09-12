import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError, DoesNotExist

from sanic_security.exceptions import (
    ExistsError,
    NotFoundError,
    AccountError, SessionError,
)
from sanic_security.models import Account, SessionFactory, AuthenticationSession
from sanic_security.utils import hash_password

session_factory = SessionFactory()


async def register(
        request: Request, verified: bool = False, disabled: bool = False
) -> Account:
    """
    Registers a new account to be used by a client.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, username, password, phone (including country code).
        verified (bool): If false, account being registered must be verified before use.
        disabled (bool): If true, account being registered must be enabled before use.

    Returns:
        account

    Raises:
        AccountError
    """
    if not re.search("[^@]+@[^@]+.[^@]+", request.form["email"]):
        raise AccountError("Please use a valid email format such as you@mail.com.", 400)
    if request.form["phone"] and (
            not request.form["phone"].isdigit() or len(request.form["phone"]) < 11
    ):
        raise AccountError(
            "Please use a valid phone format such as 15621435489 or 19498963648018.",
            400,
        )
    try:
        account = await Account.create(
            email=request.form["email"],
            username=request.form["username"],
            password=hash_password(request.form["password"]),
            phone=request.form["phone"],
            verified=verified,
            disabled=disabled,
        )
        return account
    except IntegrityError as ie:
        if ie.args[0].args[0] == 1062:
            raise ExistsError()
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
        two_factor (bool): Determines if login requires a second factor to authenticate account.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    try:
        if not account:
            account = await Account.get_via_email(request.form["email"])
            if account.password == hash_password(request.form["password"]):
                account.validate()
                return await session_factory.get(
                    "authentication", request, account, two_factor=two_factor
                )
            else:
                raise AccountError("Incorrect password!", 401)
    except DoesNotExist:
        raise NotFoundError("An account with this email does not exist.")


async def validate_second_factor(request: Request) -> AuthenticationSession:
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
