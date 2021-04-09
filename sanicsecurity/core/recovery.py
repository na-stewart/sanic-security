from sanic.request import Request

from sanicsecurity.core.authentication import account_error_factory
from sanicsecurity.core.models import AuthenticationSession, Account, VerificationSession
from sanicsecurity.core.utils import hash_pw
from sanicsecurity.core.verification import request_verification


async def account_recovery(request: Request, verification_session: VerificationSession):
    """
    Recovers an account by setting the password to a new one.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    password.

    :param verification_session: Verification session containing account being recovered.

    return: verification_session
    """
    verification_session.account.password = hash_pw(request.form.get('password'))
    await AuthenticationSession.filter(account=verification_session.account, valid=True,
                                       deleted=False).update(valid=False)
    await verification_session.account.save(update_fields=['password'])
    return verification_session


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
