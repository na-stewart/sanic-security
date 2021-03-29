import functools
import re

import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError, ValidationError

from asyncauth.core.models import Account, SessionFactory, AuthenticationSession, VerificationSession, Session
from asyncauth.core.utils import hash_password
from asyncauth.core.verification import request_verification

session_factory = SessionFactory()
account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def account_recovery(request: Request, verification_session: VerificationSession):
    """
    Recovers an account by setting the password to a new one passed through the method.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    password.

    :param verification_session: Verification session containing account being verified.
    """
    verification_session.account.password = hash_password(request.form.get('password'))
    await AuthenticationSession.filter(account=verification_session.account, valid=True,
                                       deleted=False).update(valid=False)
    await verification_session.account.save(update_fields=['password'])


async def request_account_recovery(request: Request):
    """
    Requests a verification session to ensure that the recovery attempt was made by the account owner.

    :param request: Sanic request parameter. This request is sent with the following url argument: email.

    return: verification_session
    """

    account = await Account.filter(email=request.args.get('email')).first()
    account_error_factory.throw(account)
    verification_session = await request_verification(request, account)
    return verification_session


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    Creates a new account. This is the recommend and most secure method for registering accounts' with Async Auth.

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
    account_error_factory.throw(account)
    if bcrypt.checkpw(form.get('password').encode('utf-8'), account.password):
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
