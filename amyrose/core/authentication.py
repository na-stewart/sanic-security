import bcrypt
import jwt
from tortoise.exceptions import IntegrityError

from amyrose import config_parser
from amyrose.core.models import Account, VerificationSession, AccountErrorFactory, AuthenticationSession, \
    SessionErrorFactory, IncorrectPasswordError, Session, Role
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
    client_uid = request.headers.get('X-Client-Uid')
    return await Account.filter(uid=client_uid).first()


async def register(request):
    params = request.form
    hashed_pass = bcrypt.hashpw(params.get('password').encode('utf8'), bcrypt.gensalt())
    try:
        account = await Account.create(email=params.get('email'), username=params.get('username'), password=hashed_pass,
                                       phone=params.get('phone'))
        verification_session = await VerificationSession.create(parent_uid=account.uid, expiration_date=best_by(1))
        return account, verification_session
    except IntegrityError:
        raise Account.AccountExistsError()


async def verify_account(request):
    params = request.form
    token = request.cookies.get('veritkn')
    verification_session_query = VerificationSession.filter(token=token)
    verification_session = await verification_session_query.first()
    session_error_factory.raise_error(verification_session)
    if verification_session.code != params.get('code'):
        raise VerificationSession.InvalidCodeError()
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
        raise IncorrectPasswordError()


async def authenticate(request):
    if url_endpoint(request.url) in endpoints_requiring_authentication:
        token = request.cookies.get('authtkn')
        authentication_session = await AuthenticationSession.filter(token=token).first()
        session_error_factory.raise_error(authentication_session)
        account_error_factory.raise_error(await Account.filter(uid=authentication_session.parent_uid).first())
        return authentication_session


def requires_authentication(*args, **kwargs):
    def inner(func):
        endpoints_requiring_authentication.append(args[0])
        return func

    return inner


async def generate_admin_account():
    if not await Account.exists():
        account = await Account.create(email=config_parser['ROSE']['admin_email'],
                                       phone=config_parser['ROSE']['admin_phone'],
                                       username=config_parser['ROSE']['admin_username'],
                                       password=config_parser['ROSE']['admin_password'], verified=True)
        await Role(parent_uid=account.uid, role_name='Admin')
