import functools

import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError

from amyrose.core.dto import AccountDTO, AuthenticationSessionDTO
from amyrose.core.models import Account, AuthenticationSession, Session
from amyrose.core.utils import best_by
from amyrose.core.verification import request_verification

account_dto = AccountDTO()
authentication_session_dto = AuthenticationSessionDTO()
account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def register(request: Request):
    """
    Creates an unverified account. This is the recommend and most secure method for registering accounts' with Amy Rose.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, password, phone.

    :raises AccountExistsError:

    :return: account, verification_session
    """
    params = request.form
    try:
        account = await account_dto.create(email=params.get('email'), username=params.get('username'),
                                           password=account_dto.hash_password(params.get('password')),
                                           phone=params.get('phone'))
        return await request_verification(request, account)
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
    account = await account_dto.get_by_email(params.get('email'))
    account_error_factory.raise_error(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await authentication_session_dto.create(parent_uid=account.uid, ip=request.ip,
                                                                         expiration_date=best_by(30))
        return account, authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def logout(request: Request):
    """
    Invalidates client's authentication session.

    :param request: Sanic request parameter.

    :return: account, authentication_session
    """
    account, authentication_session = await authenticate(request)
    authentication_session.valid = False
    await authentication_session_dto.update(authentication_session, fields=['valid'])
    return account, authentication_session


async def authenticate(request: Request):
    """
    Verifies the client's authentication session.

    :param request: Sanic request parameter.

    :raises SessionError:

    :raises AccountError:

    :return: account, authentication_session
    """
    authentication_session = await AuthenticationSession().decode(request)
    session_error_factory.raise_error(authentication_session)
    account = await account_dto.get(authentication_session.parent_uid)
    account_error_factory.raise_error(account)
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
