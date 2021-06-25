from sanic.request import Request

from sanic_security.models import (
    AuthenticationSession,
    Account,
    TwoStepSession,
    AccountErrorFactory,
    SessionFactory,
)
from sanic_security.utils import hash_password

account_error_factory = AccountErrorFactory()
session_factory = SessionFactory()


async def recover_password(request: Request, two_step_session: TwoStepSession):
    """
    Recovers an account by changing the password once recovery request was determined to be made by the account owner
    via requiring two-step verification.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: password.
        two_step_session (TwoStepSession): Two-step session containing account being recovered.

    """
    two_step_session.account.password = hash_password(request.form.get("password"))
    await AuthenticationSession.filter(
        account=two_step_session.account, valid=True, deleted=False
    ).update(valid=False)
    await two_step_session.account.save(update_fields=["password"])


async def request_password_recovery(request: Request):
    """
    Requests a two-step session to ensure that recovery request was made by the account owner.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.

    Returns:
        two_step_session
    """

    account = await Account.get_via_email(request.form.get("email"))
    account_error_factory.throw(account)
    return await session_factory.get("twostep", request, account=account)
