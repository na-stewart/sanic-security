import functools

import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError

from amyrose.core.dto import AccountDTO, AuthenticationSessionDTO, VerificationSessionDTO
from amyrose.core.models import Account, VerificationSession, AuthenticationSession, Session
from amyrose.core.utils import best_by

account_dto = AccountDTO()
authentication_session_dto = AuthenticationSessionDTO()
verification_session_dto = VerificationSessionDTO()
account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def _request_verification(request: Request, account: Account):
    """
        Creates a verification session associated with an account. Invalidates all previous verification requests.

       :param request: Sanic request parameter.

       :param account: The account that requires verification.

       :return: account, verification_session
       """
    account.verified = False
    await account_dto.update(account, ['verified'])
    await verification_session_dto.invalidate_previous_sessions(account)
    verification_session = await verification_session_dto.create(expiration_date=best_by(1), parent_uid=account.uid,
                                                           ip=request.ip)
    return account, verification_session


async def register(request: Request):
    """
    Creates an unverified account. This is the recommend and most secure method for registering accounts' with Amy Rose.
    email, username, phone, and password.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, password, phone.

    :raises AccountExistsError:

    :return: account, verification_session
    """
    params = request.form
    try:
        hashed = bcrypt.hashpw(params.get('password').encode('utf8'), bcrypt.gensalt())

        account = await account_dto.create(email=params.get('email'), username=params.get('username'),
                                           password=hashed, phone=params.get('phone'))
        return await _request_verification(request, account)
    except IntegrityError:
        raise Account.AccountExistsError()


async def _complete_verification(account: Account, verification_session: VerificationSession):
    """
    The last step in the verification process which is too verify the account and invalidate the session after use.

    :param account: account to be verified.

    :param verification_session: session to be invalidated after use.

    :return: account, verification_session
    """
    verification_session.valid = False
    account.verified = True
    await account_dto.update(account, ['verified'])
    await verification_session_dto.update(verification_session, ['valid'])
    return account, verification_session


async def verify_account(request: Request):
    """
    Verifies an account for use using a code sent via email or text.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :raises SessionError:

    :return: account, verification_session
    """
    verification_session = await VerificationSession().decode(request)
    if verification_session.code != request.form.get('code'):
        raise VerificationSession().IncorrectCodeError()
    else:
        session_error_factory.raise_error(verification_session)
        account = await account_dto.get(verification_session.parent_uid)
    return await _complete_verification(account, verification_session)


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
    await authentication_session_dto.update(authentication_session)
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
