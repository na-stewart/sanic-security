import functools
import re

import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from asyncauth.core.models import Account, SessionFactory, AuthenticationSession, RecoverySession
from asyncauth.core.utils import hash_password
from asyncauth.core.verification import request_verification

session_factory = SessionFactory()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Creates a new account. This is the recommend and most secure method for registering accounts' with Async Auth.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, password, phone.

    :param verified: If false, account being registered must be verified before use.

    :param disabled: If true, account being registered must be enabled before use.

    :raises AccountError:

    :return: account if verified or  verification_session if not verified
    """
    forms = request.form
    if not re.search('[^@]+@[^@]+.[^@]+', forms.get('email')):
        raise Account.InvalidEmailError()
    try:
        account = await Account.create(email=forms.get('email'), username=forms.get('username'),
                                       password=hash_password(forms.get('password')),
                                       phone=forms.get('phone'), verified=verified, disabled=disabled)
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
    Account.ErrorFactory(account)
    if bcrypt.checkpw(form.get('password').encode('utf-8'), account.password):
        authentication_session = await session_factory.get('authentication', request, account=account)
        return authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def request_recovery(request: Request):
    """
    Creates a recovery session associated with an account.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, password.

    :return: recovery_session
    """
    form = request.form
    account = await Account.filter(email=form.get('email')).first()
    return await session_factory.get('verification', request, account=account, password=form.get('password'))


async def recover(request: Request):
    """
    Recovers an account by updating it's password to the recovery session password.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :raises SessionError:

    :return: verification_session
    """
    recovery_session = await RecoverySession().decode(request)
    if recovery_session.code != request.form.get('code'):
        raise RecoverySession.VerificationAttemptError()
    else:
        Account.ErrorFactory(recovery_session.account)
        RecoverySession.ErrorFactory(recovery_session)
    recovery_session.account.password = recovery_session.password
    recovery_session.valid = False
    await recovery_session.account.save(update_fields=['password'])
    await recovery_session.save(update_fields=['valid'])
    return recovery_session


async def logout(request: Request):
    """
    Invalidates client's authentication session.

    :param request: Sanic request parameter.
    """
    authentication_session = await AuthenticationSession().decode(request)
    authentication_session.valid = False
    authentication_session.save(update_fields=['valid'])
    return authentication_session


async def authenticate(request: Request):
    """
    Authenticated the client's current authentication session.

    :param request: Sanic request parameter.

    :raises SessionError:

    :raises AccountError:

    :return: authentication_session
    """

    authentication_session = await AuthenticationSession().decode(request)
    await authentication_session.verify_location(request)
    AuthenticationSession.ErrorFactory(authentication_session)
    Account.ErrorFactory(authentication_session.account)
    return authentication_session


def requires_authentication():
    """
    Has the same function as the authenticate method, but is in the form of a decorator.

    :raises AccountError:

    :raises SessionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper
