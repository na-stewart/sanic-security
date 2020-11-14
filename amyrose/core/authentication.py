import bcrypt
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Account, VerificationSession, AccountErrorFactory, AuthenticationSession, \
    SessionErrorFactory
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


async def get_client(request):
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    return await Account.filter(uid=decoded_cookie['parent_uid']).first()


async def register(request):
    params = request.form
    try:
        account = await Account.create(email=params.get('email'), username=params.get('username'),
                                       password=_hash_pass(params.get('password')), phone=params.get('phone'))
        verification_session = await VerificationSession().create(parent_uid=account.uid, expiration_date=best_by(1))
        return account, verification_session
    except IntegrityError:
        raise Account.AccountExistsError()


async def verify_account(request):
    params = request.form
    decoded_cookie = VerificationSession.from_cookie(request.cookies.get('veritkn'))
    verification_session_query = VerificationSession.filter(uid=decoded_cookie['uid'])
    verification_session = await verification_session_query.first()
    session_error_factory.raise_error(verification_session)
    if verification_session.code != params.get('code'):
        raise VerificationSession.IncorrectCodeError()
    await Account.filter(uid=verification_session.parent_uid).update(verified=True)
    await verification_session_query.update(valid=False)


async def login(request):
    params = request.form
    account_query = Account.filter(email=params.get('email'))
    account = await account_query.first()
    account_error_factory.raise_error(account)
    if bcrypt.checkpw(params.get('password').encode('utf-8'), account.password):
        authentication_session = await AuthenticationSession.create(parent_uid=account.uid, expiration_date=best_by(30))
        return account, authentication_session
    else:
        raise Account.IncorrectPasswordError()


async def authenticate(request):
    if url_endpoint(request.url) in endpoints_requiring_authentication:
        decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
        authentication_session = await AuthenticationSession.filter(uid=decoded_cookie['uid']).first()
        account = await Account.filter(uid=authentication_session.parent_uid).first()
        session_error_factory.raise_error(authentication_session)
        account_error_factory.raise_error(account)
        return account


def append_endpoints_requiring_authentication(endpoint):
    if endpoint not in endpoints_requiring_authentication:
        endpoints_requiring_authentication.append(endpoint)


def requires_authentication(*args, **kwargs):
    def inner(func):
        append_endpoints_requiring_authentication(args[0])
        return func

    return inner


def _hash_pass(password):
    return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
