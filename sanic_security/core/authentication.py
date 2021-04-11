import functools
import re

from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from sanic_security.core.models import Account, SessionFactory, AuthenticationSession, Session
from sanic_security.core.utils import hash_pw
from sanic_security.core.verification import request_verification

session_factory = SessionFactory()
account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Creates a new account. This is the recommend and most secure method for registering accounts' with sanic-security.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, password, phone.

    :param verified: If false, account being registered must be verified before use.

    :param disabled: If true, account being registered must be enabled before use.

    :raises AccountError:

    :return: account if verified or verification_session if not verified
    """
    forms = request.form
    if not re.search('[^@]+@[^@]+.[^@]+', forms.get('email')):
        raise Account.InvalidEmailError()
    try:
        account = await Account.create(email=forms.get('email'), username=forms.get('username'),
                                       password=hash_pw(forms.get('password')), phone=forms.get('phone'),
                                       verified=verified, disabled=disabled)
        return await request_verification(request, account) if not verified else account
    except IntegrityError:
        raise Account.ExistsError()
    except ValidationError:
        raise Account.TooManyCharsError()


async def login(request: Request):
    """
    Creates an authentication session that is used to verify the account making requests requiring authentication.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, password.

    :raises AccountError:

    :return: authentication_session
    """
    form = request.form
    account = await Account.filter(email=form.get('email')).first()
    account_error_factory.throw(account)
    if account.password == hash_pw(form.get('password')):
        authentication_session = await session_factory.get('authentication', request, account=account)
        return authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def logout(request: Request):
    """
    Invalidates client's authentication session.

    :param request: Sanic request parameter.
    """
    authentication_session = await AuthenticationSession().decode(request)
    authentication_session.valid = False
    await authentication_session.save(update_fields=['valid'])
    return authentication_session


async def authenticate(request: Request):
    """
    Authenticates the client's current authentication session.

    :raises AccountError:

    :raises SessionError:

    :return: authentication_session
    """
    authentication_session = await AuthenticationSession().decode(request)
    session_error_factory.throw(authentication_session)
    await authentication_session.crosscheck_location(request)
    account_error_factory.throw(authentication_session.account)
    return authentication_session


def requires_authentication():
    """
    Authenticates the client's current authentication session.

    :raises AccountError:

    :raises SessionError:

    :return: func(request, authentication_session, *args, **kwargs)
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await authenticate(request)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper
