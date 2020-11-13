import functools

import bcrypt
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Account, VerificationSession, AccountErrorFactory, AuthenticationSession, \
    SessionErrorFactory, IncorrectPasswordError
from amyrose.core.utils import best_by, url_endpoint

session_error_factory = SessionErrorFactory()
account_error_factory = AccountErrorFactory()
endpoints_requiring_authentication = []


def client_ip(request):
    try:
        ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or \
             request.remote_ip
    except AttributeError:
        ip = None
    return ip


async def register(request, requires_verification=True):
    params = request.form
    hashed_pass = bcrypt.hashpw(params.get('password').encode('utf8'), bcrypt.gensalt())
    verification_session = None
    try:
        account = await Account.create(email=params.get('email'), username=params.get('username'), password=hashed_pass,
                                       phone=params.get('phone'), verified=not requires_verification)
        if requires_verification:
            verification_session = await VerificationSession.create(parent_uid=account.uid, expiration_date=best_by(1))
        return verification_session, account
    except IntegrityError:
        raise Account.AccountExistsError()


async def verify_account(request):
    params = request.form
    verification_session_query = VerificationSession.filter(token=request.cookies.get('veritkn'))
    verification_session = await verification_session_query.first()
    session_error_factory.raise_error(verification_session)
    if verification_session.code != params.get('code'):
        raise VerificationSession.InvalidCodeError()
    await Account.filter(uid=verification_session.parent_uid).update(verified=True)
    await verification_session_query.update(valid=False)


async def login(request):
    params = request.form
    account = await Account.filter(email=params.get('email')).first()
    account_error_factory.raise_error(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await AuthenticationSession.create(parent_uid=account.uid, expiration_date=best_by(30))
        return account, authentication_session
    else:
        raise IncorrectPasswordError()


async def authenticate(request):
    print(url_endpoint(request.url))
    if url_endpoint(request.url) in endpoints_requiring_authentication:
        authentication_session = await AuthenticationSession.filter(token=request.cookies.get('authtkn')).first()
        session_error_factory.raise_error(authentication_session)
        account_error_factory.raise_error(await Account.filter(uid=authentication_session.parent_uid).first())
        return authentication_session


def requires_authentication(*args, **kwargs):
    def inner(func):
        if args[0] not in endpoints_requiring_authentication:
            endpoints_requiring_authentication.append(args[0])
        return func

    return inner