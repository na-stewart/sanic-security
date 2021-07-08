import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.exceptions import (
    PasswordIncorrectError,
    ExistsError,
    InvalidIdentifierError,
    NotFoundError,
)
from sanic_security.models import (
    Account,
    SessionFactory,
    AuthenticationSession,
    AccountErrorFactory,
    SessionErrorFactory,
)
from sanic_security.utils import hash_password
from sanic_security.verification import request_two_step_verification

session_factory = SessionFactory()
account_error_factory = AccountErrorFactory()
session_error_factory = SessionErrorFactory()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Creates a new account. This is the recommend method for creating accounts' with Sanic Security.

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
        raise InvalidIdentifierError(
            "Please use a valid email format such as you@mail.com."
        )
    if form.get("phone") and (
        not form.get("phone").isdigit() or len(form.get("phone")) < 11
    ):
        raise InvalidIdentifierError(
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
            await request_two_step_verification(request, account, True)
            if not verified
            else account
        )
    except IntegrityError as ie:
        if ie.args[0].args[0] == 1062:
            raise ExistsError()
        else:
            raise ie
    except ValidationError:
        raise InvalidIdentifierError(
            "Email, username, or phone number is too long or invalid."
        )


async def login(request: Request, account: Account = None):
    """
    Used to login to accounts registered with Sanic Security.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, password.
        account (Account): Account being logged into.

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
            account_error_factory.throw(account)
            authentication_session = await session_factory.get(
                "authentication", request, account=account
            )
            return authentication_session
        else:
            raise PasswordIncorrectError()
    else:
        raise NotFoundError("An account with this email does not exist.")


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
    authentication_session = await AuthenticationSession().decode(request)
    account_error_factory.throw(authentication_session.account)
    session_error_factory.throw(authentication_session)
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
