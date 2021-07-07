from sanic.request import Request

from sanic_security.models import (
    AuthenticationSession,
    TwoStepSession,
)
from sanic_security.utils import hash_password


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
