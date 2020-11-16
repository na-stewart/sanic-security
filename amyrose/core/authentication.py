import functools
import bcrypt
from tortoise.exceptions import IntegrityError
from amyrose.core.models import Account, VerificationSession, AuthenticationSession, Session
from amyrose.core.utils import best_by, is_expired

account_error_factory = Account.ErrorFactory()
session_error_factory = Session.ErrorFactory()


async def get_client(request):
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    account = await Account.filter(uid=decoded_cookie['parent_uid']).first()
    account_error_factory.raise_error(account)
    return account


async def register(request):
    params = request.form
    try:
        account = await Account.create(email=params.get('email'), username=params.get('username'),
                                       password=_hash_pass(params.get('password')), phone=params.get('phone'))
        verification_session = await VerificationSession().create(ip=request.ip, parent_uid=account.uid,
                                                                  expiration_date=best_by(1))
        return account, verification_session
    except IntegrityError:
        raise Account.AccountExistsError()


async def verify_account(request):
    params = request.form
    decoded_cookie = VerificationSession.from_cookie(request.cookies.get('veritkn'))
    verification_session = await VerificationSession.filter(uid=decoded_cookie['uid']).first()
    account = await Account.filter(uid=verification_session.parent_uid).first()
    if verification_session.code != params.get('code'):
        raise VerificationSession.IncorrectCodeError()
    else:
        session_error_factory.raise_error(verification_session, request)
    verification_session.valid = False
    account.verified = True
    await account.save(update_fields=['verified'])
    await verification_session.save(update_fields=['valid'])
    return account, verification_session


async def login(request):
    params = request.form
    account = await Account.filter(email=params.get('email')).first()
    account_error_factory.raise_error(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await AuthenticationSession.create(parent_uid=account.uid,
                                                                    ip=request.ip, expiration_date=best_by(30))
        session_error_factory.raise_error(authentication_session, request)
        return account, authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def logout(request):
    account, authentication_session = await authenticate(request)
    authentication_session.valid = False
    await authentication_session.save(update_fields=['valid'])
    return account, authentication_session


async def authenticate(request):
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    authentication_session = await AuthenticationSession.filter(uid=decoded_cookie['uid']).first()
    account = await Account.filter(uid=authentication_session.parent_uid).first()
    session_error_factory.raise_error(authentication_session, request)
    account_error_factory.raise_error(account)
    return account, authentication_session


def requires_authentication():
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


def _hash_pass(password):
    return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
