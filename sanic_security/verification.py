import functools

from sanic.request import Request

from sanic_security.exceptions import UnverifiedError
from sanic_security.models import (
    Account,
    TwoStepSession,
    SessionFactory,
    SessionErrorFactory,
    AccountErrorFactory,
)

session_factory = SessionFactory()
session_error_factory = SessionErrorFactory()
account_error_factory = AccountErrorFactory()


def _raise_account_error(account):
    """
    Circumvents an account unverified error retrieved from the account error factory as this module is utilised to verify unverified accounts.

    Args:
        account (Account): account being passed to the error factory.
    """
    account_error = account_error_factory.get(account)
    if account_error and not isinstance(account_error, UnverifiedError):
        raise account_error


async def request_two_step_verification(request: Request, account=None):
    """
    Creates a two-step session associated with an account.

    Args:
        request (Request): Sanic request parameter.
        account (Account): The account being associated with the verification session. Will retrieve account via email if no account is passed.

    Returns:
         two_step_session
    """
    if not account:
        account = await Account.get_via_email(request.form.get("email"))
    _raise_account_error(account)
    return await session_factory.get("twostep", request, account=account)


async def verify_account(two_step_session: TwoStepSession):
    """
    Used to verify an account associated to an existing two-step session.

    Args:
        two_step_session (TwoStepSession): Two-step session containing account being verified.

    Raises:
        SessionError

    Returns:
         two_step_session
    """
    two_step_session.account.verified = True
    await two_step_session.account.save(update_fields=["verified"])
    return two_step_session


async def two_step_verification(request: Request):
    """
    Verifies a two-step verification attempt.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: code.

    Raises:
        SessionError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession().decode(request)
    session_error_factory.throw(two_step_session)
    _raise_account_error(two_step_session.account)
    await two_step_session.crosscheck_location(request)
    await two_step_session.crosscheck_code(request.form.get("code"))
    return two_step_session


def requires_two_step_verification():
    """
    Verifies a two-step challenge attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/captcha')
            @requires_two_step_verification()
            async def on_two_step_verification(request, two_step_session):
                return text('User has successfully provided the correct verification code from email/sms!')

    Raises:
        SessionError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            two_step_session = await two_step_verification(request)
            return await func(request, two_step_session, *args, **kwargs)

        return wrapped

    return wrapper
