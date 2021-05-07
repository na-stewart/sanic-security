from sanic.request import Request

from sanic_security.core.models import (
    AuthenticationSession,
    Account,
    TwoStepSession,
    AccountErrorFactory,
)
from sanic_security.core.utils import hash_password
from sanic_security.core.verification import request_two_step_verification

account_error_factory = AccountErrorFactory()


async def fulfill_account_recovery_attempt(
    request: Request, two_step_session: TwoStepSession
):
    """
    Recovers an account by setting the password to a new one once recovery attempt was determined to be made
    by the account owner.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: password.
        two_step_session (TwoStepSession): Two-step session containing account being recovered.

    """
    two_step_session.account.password = hash_password(request.form.get("password"))
    await AuthenticationSession.filter(
        account=two_step_session.account, valid=True, deleted=False
    ).update(valid=False)
    await two_step_session.account.save(update_fields=["password"])


async def attempt_account_recovery(request: Request):
    """
    Requests a two-step session to ensure that the recovery attempt was made by the account owner.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.

    Returns:
        two_step_session: A new two-step session for the client is created with all identifying information
        on request and requires encoding.
    """

    account = await Account.get_via_email(request.form.get("email"))
    account_error_factory.throw(account)
    return await request_two_step_verification(request, account)
