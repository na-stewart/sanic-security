import functools

from sanic.request import Request

from sanic_security.exceptions import UnverifiedError
from sanic_security.models import (
    Account,
    TwoStepSession,
    SessionFactory,
)
from sanic_security.validation import validate_account, validate_session

session_factory = SessionFactory()


def _validate_account(account: Account, allow_unverified: bool):
    """
    Validates an account by determining if an error should be raised due to variable values.

    Args:
        account (Account): The account being validated.
        allow_unverified (bool):  Prevents an unverified account from raising an unverified error.

    Raises:
        AccountError
    """
    try:
        validate_account(account)
    except UnverifiedError as e:
        if not allow_unverified:
            raise e


async def request_two_step_verification(
    request: Request,
    account=None,
    allow_unverified=False,
):
    """
    Creates a two-step session associated with an account.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.
        account (Account): The account being associated with the verification session. If None, an account is retrieved via email with the form-data argument.
        allow_unverified (bool): Prevents an unverified account from raising an unverified error.
        metadata (Any): Metadata included in two-step verification session.

    Returns:
         two_step_session
    """
    if not account:
        account = await Account.get_via_email(request.form.get("email"))
    _validate_account(account, allow_unverified)
    two_step_session = await session_factory.get("twostep", request, account)
    return two_step_session


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
        allow_unverified (bool): Prevents an unverified account from raising an unverified error.

    Raises:
        SessionError
        AccountError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)
    _validate_account(two_step_session.account, allow_unverified)
    validate_session(two_step_session)
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
