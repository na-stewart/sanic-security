from sanic.request import Request

from sanic_security.core.authentication import account_error_factory
from sanic_security.core.models import AuthenticationSession, Account, TwoStepSession
from sanic_security.core.utils import hash_pw
from sanic_security.core.verification import request_two_step_verification


async def fulfill_account_recovery_attempt(request: Request, two_step_session: TwoStepSession):
    """
    Recovers an account by setting the password to a new one once recovery attempt was determined to be made
    by the account owner.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    password.

    :param two_step_session: Verification session containing account being recovered.
    """
    two_step_session.account.password = hash_pw(request.form.get('password'))
    await AuthenticationSession.filter(account=two_step_session.account, valid=True,
                                       deleted=False).update(valid=False)
    await two_step_session.account.save(update_fields=['password'])


async def attempt_account_recovery(request: Request):
    """
    Requests a verification session to ensure that the recovery attempt was made by the account owner.

    :param request: Sanic request parameter. This request is sent with the following url argument: email.

    return: verification_session
    """

    account = await Account.filter(email=request.form.get('email')).first()
    account_error_factory.throw(account)
    return await request_two_step_verification(request, account)
