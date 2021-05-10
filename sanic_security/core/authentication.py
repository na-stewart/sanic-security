import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.core.exceptions import (
    PasswordMismatchError,
    InvalidEmailError,
    ExistsError,
    TooManyCharsError,
    NotFoundError,
)
from sanic_security.core.models import (
    Account,
    SessionFactory,
    AuthenticationSession,
    AccountErrorFactory,
    SessionErrorFactory,
)
from sanic_security.core.utils import hash_password
from sanic_security.core.verification import request_two_step_verification

session_factory = SessionFactory()
account_error_factory = AccountErrorFactory()
session_error_factory = SessionErrorFactory()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Creates a new account. This is the recommend method for creating accounts' with Sanic Security.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email, username, password, phone.
        verified (bool): If false, account being registered must be verified before use.
        disabled (bool): If true, account being registered must be enabled before use.

    Returns:
        account: An account is returned if the verified parameter is true.
        two_step_session: A two-step session is returned if the verified parameter is false.

    Raises:
        AccountError
    """
    forms = request.form
    if not re.search("[^@]+@[^@]+.[^@]+", forms.get("email")):
        raise InvalidEmailError()
    try:
        account = await Account.create(
            email=forms.get("email"),
            username=forms.get("username"),
            password=hash_password(forms.get("password")),
            phone=forms.get("phone"),
            verified=verified,
            disabled=disabled,
        )
        return (
            await request_two_step_verification(request, account)
            if not verified
            else account
        )
    except IntegrityError:
        raise ExistsError()
    except ValidationError:
        raise TooManyCharsError()


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
    """
    form = request.form
    account = await Account.get_via_email(form.get("email")) if not account else account
    if account:
        if account.password == hash_password(form.get("password")):
            account_error_factory.throw(account)
            authentication_session = await session_factory.get(
                "authentication", request, account=account
            )
            return authentication_session
        else:
            raise PasswordMismatchError()
    else:
        raise NotFoundError("This account does not exist.")


async def logout(request: Request):
    """
    Invalidates client's authentication session and revokes access.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession().decode(request)
    authentication_session.valid = False
    await authentication_session.save(update_fields=["valid"])
    return authentication_session


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
    session_error_factory.throw(authentication_session)
    await authentication_session.crosscheck_location(request)
    account_error_factory.throw(authentication_session.account)
    return authentication_session


def requires_authentication():
    """
    Enforces authentication to continue execution.

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
