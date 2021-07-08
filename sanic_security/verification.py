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


def _validate_account(account: Account, allow_unverified: bool):
    """
    Validates that an account used for verification does not have any error conditions and also will bypass any unverified errors
    if allow_unverified is true.

    Args:
        account (Account): The account being validated.
        allow_unverified (bool): Prevents an account unverified error from raising when true, best used for registration cases.

    Raises:
        AccountError
    """
    account_error = account_error_factory.get(account)
    if account_error:
        if isinstance(account_error, UnverifiedError):
            if not allow_unverified:
                raise account_error
        else:
            raise account_error


async def request_two_step_verification(
    request: Request, account=None, allow_unverified=False
):
    """
    Creates a two-step session associated with an account.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.
        account (Account): The account being associated with the verification session.
        allow_unverified (bool): Prevents an account unverified error from raising when true, best used for registration cases.

    Returns:
         two_step_session
    """
    if not account:
        account = await Account.get_via_email(request.form.get("email"))
    _validate_account(account, allow_unverified)
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


async def two_step_verification(request: Request, allow_unverified=False):
    """
    Verifies a two-step verification attempt.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: code.
        allow_unverified (bool): Prevents an account unverified error from raising when true, best used for registration cases.

    Raises:
        SessionError
        AccountError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession().decode(request)
    _validate_account(two_step_session.account, allow_unverified)
    session_error_factory.throw(two_step_session)
    await two_step_session.crosscheck_location(request)
    await two_step_session.crosscheck_code(request.form.get("code"))
    return two_step_session


def requires_two_step_verification(allow_unverified=False):
    """
    Verifies a two-step challenge attempt.

    Args:
        allow_unverified (bool): Prevents an account unverified error from raising when true, best used for registration cases.


    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/verification/attempt")
            @requires_two_step_verification()
            async def on_verified(request, two_step_session):
                response = json("Two-step verification attempt successful!", two_step_session.json())
                return response

    Raises:
        SessionError
        AccountError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            two_step_session = await two_step_verification(request, allow_unverified)
            return await func(request, two_step_session, *args, **kwargs)

        return wrapped

    return wrapper
