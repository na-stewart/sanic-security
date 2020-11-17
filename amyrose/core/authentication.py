import functools

import bcrypt
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Account, VerificationSession, AuthenticationSession, Session
from amyrose.core.utils import best_by

account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def get_client(request):
    """
    Retrieves account information from an authentication session found within cookie.

    :param request: Sanic request parameter.

    :return: account
    """
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    account = await Account.filter(uid=decoded_cookie['parent_uid']).first()
    return account


async def create_account(email, phone, username, password, verified):
    """
    This method should not be used for regular user registration. The intent is to make it easy for
    developers and administrators to instantly create accounts.

    :return: account
    """
    try:
        return await Account.create(email=email, username=username, password=_hash_pass(password), phone=phone,
                                    verified=verified)
    except IntegrityError:
        raise Account.AccountExistsError()


async def delete_account(email):
    """
    Renders an account inoperable while remaining on the database.

    :param email:

    :return: account
    """
    account = await Account.filter(email=email).first()
    account.deleted = True
    await account.save(update_fields=['deleted'])
    return account


async def register(request):
    """
    Creates an unverified account. This is the recommend and most secure method for registering accounts' with Amy Rose.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    email, username, phone, and password.

    :return: account, verification_session
    """
    params = request.form
    try:
        account = await create_account(params.get('email'), params.get('username'), params.get('password'),
                                       params.get('phone'), False)
        verification_session = await VerificationSession().create(ip=request.ip, parent_uid=account.uid,
                                                                  expiration_date=best_by(1))
        return account, verification_session
    except IntegrityError:
        raise Account.AccountExistsError()


async def verify_account(request):
    """
    Verifies an account for use using a code sent via email or text.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :return: account, verification_session
    """
    params = request.form
    decoded_cookie = VerificationSession.from_cookie(request.cookies.get('veritkn'))
    verification_session = await VerificationSession.filter(uid=decoded_cookie['uid']).first()
    account = await Account.filter(uid=verification_session.parent_uid).first()
    if verification_session.code != params.get('code'):
        raise VerificationSession.IncorrectCodeError()
    else:
        session_error_factory.get(verification_session, request)
    verification_session.valid = False
    account.verified = True
    await account.save(update_fields=['verified'])
    await verification_session.save(update_fields=['valid'])
    return account, verification_session


async def login(request):
    """
    Creates an authentication session that is used to verify the account making requests requiring authentication.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument:
    email.

    :return: account, authentication_session
    """
    params = request.form
    account = await Account.filter(email=params.get('email')).first()
    account_error_factory.get(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await AuthenticationSession.create(parent_uid=account.uid,
                                                                    ip=request.ip, expiration_date=best_by(30))
        session_error_factory.get(authentication_session, request)
        return account, authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def logout(request):
    """
    Invalidates client's authentication session.

    :param request: Sanic request parameter.

    :return: account, authentication_session
    """
    account, authentication_session = await authenticate(request)
    authentication_session.valid = False
    await authentication_session.save(update_fields=['valid'])
    return account, authentication_session


async def authenticate(request):
    """
    Verifies the client's authentication session.

    :param request: Sanic request parameter.

    :return: account, authentication_session
    """
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    authentication_session = await AuthenticationSession.filter(uid=decoded_cookie['uid']).first()
    account = await Account.filter(uid=authentication_session.parent_uid).first()
    session_error_factory.get(authentication_session, request)
    account_error_factory.get(account)
    return account, authentication_session


def requires_authentication():
    """
    A decorator used to authenticate a client before executing a method.
    """
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


def _hash_pass(password):
    return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
