import functools
import re

import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Account, AuthenticationSession
from amyrose.core.utils import best_by, request_ip, hash_password
from amyrose.core.verification import request_verification


async def register(request: Request, requires_verification=True):
    """
    Creates an unverified account. This is the recommend and most secure method for registering accounts' with Amy Rose.

    :param requires_verification: If true, account being registered must be verified before use.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, password, phone.

    :raises AccountExistsError:

    :return: account, verification_session
    """
    forms = request.form
    if not re.search('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', forms.get('email')):
        raise Account.InvalidEmailError()
    try:
        account = await Account().create(email=forms.get('email'), username=forms.get('username'),
                                         password=hash_password(forms.get('password')),
                                         phone=forms.get('phone'), verified=not requires_verification)
        if requires_verification:
            return await request_verification(request, account)
        else:
            return account
    except IntegrityError:
        raise Account.AccountExistsError()


async def login(request: Request):
    """
    Creates an authentication session that is used to verify the account making requests requiring authentication.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, password.

    :raises SessionError:

    :raises AccountError:

    :return: account, authentication_session
    """
    params = request.form
    account = await Account().filter(email=params.get('email')).first()
    Account.ErrorFactory(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await AuthenticationSession().create(parent_uid=account.uid, ip=request_ip(request),
                                                                      expiration_date=best_by(30))
        return account, authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def logout(request: Request):
    """
    Invalidates client's authentication session.

    :param request: Sanic request parameter.
    """
    authentication_session = AuthenticationSession().decode_raw(request)
    await AuthenticationSession().filter(uid=authentication_session.get('uid')).update(valid=False)


async def authenticate(request: Request):
    """
    Verifies the client's authentication session.

    :param request: Sanic request parameter.

    :raises SessionError:

    :raises AccountError:

    :return: account, authentication_session
    """

    authentication_session = await AuthenticationSession().decode(request)
    await authentication_session.in_known_location(request)
    AuthenticationSession.ErrorFactory(authentication_session)
    account = await Account.filter(uid=authentication_session.parent_uid).first()
    Account.ErrorFactory(account)
    return account, authentication_session


def requires_authentication():
    """
    Has the same function as the authenticate method, but is in the form of a decorator and authenticates client.

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
