import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.exceptions import (
    PasswordIncorrectError,
    ExistsError,
    NotFoundError,
    SecondFactorError,
    AccountError,
)
from sanic_security.models import Account, SessionFactory, AuthenticationSession
from sanic_security.utils import hash_password
from sanic_security.validation import validate_account, validate_session

session_factory = SessionFactory()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Registers a new account to be used by a client.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, username, password, phone (including country code).
        verified (bool): If false, account being registered must be verified before use.
        disabled (bool): If true, account being registered must be enabled before use.

    Returns:
        account: An account is returned if the verified parameter is true.
        two_step_session: A two-step session is returned if the verified parameter is false.

    Raises:
        AccountError
    """
    form = request.form
    if not re.search("[^@]+@[^@]+.[^@]+", form.get("email")):
        raise AccountError("Please use a valid email format such as you@mail.com.")
    if form.get("phone") and (
        not form.get("phone").isdigit() or len(form.get("phone")) < 11
    ):
        raise AccountError(
            "Please use a valid phone format such as 15621435489 or 19498963648018."
        )
    try:
        account = await Account.create(
            email=form.get("email"),
            username=form.get("username"),
            password=hash_password(form.get("password")),
            phone=form.get("phone"),
            verified=verified,
            disabled=disabled,
        )
        return (
            await session_factory.get("twostep", request, account)
            if not verified
            else account
        )
    except IntegrityError as ie:
        if ie.args[0].args[0] == 1062:
            raise ExistsError()
        else:
            raise ie
    except ValidationError:
        raise AccountError("Email, username, or phone number is too long or invalid.")


async def login(request: Request, account: Account = None, two_factor=False):
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
    form = request.form
    if not account:
        account = await Account.get_via_email(form.get("email"))
    if account:
        if account.password == hash_password(form.get("password")):
            validate_account(account)
            return await session_factory.get(
                "authentication", request, account, two_factor=two_factor
            )
        else:
            raise PasswordIncorrectError()
    else:
        raise NotFoundError("An account with this email does not exist.")


async def validate_second_factor(request: Request):
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


async def authenticate(request: Request):
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
    validate_account(authentication_session.account)
    validate_session(authentication_session)
    if authentication_session.two_factor:
        raise SecondFactorError()
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
