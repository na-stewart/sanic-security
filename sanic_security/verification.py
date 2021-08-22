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


async def request_two_step_verification(
    request: Request,
    account=None,
):
    """
    Creates a two-step session associated with an account.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.
        account (Account): The account being associated with the verification session. If None, an account is retrieved via email with the form-data argument.

    Returns:
         two_step_session
    """
    try:
        if not account:
            account = await Account.get_via_email(request.form.get("email"))
        validate_account(account)
    except UnverifiedError:
        pass
    two_step_session = await session_factory.get("twostep", request, account)
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
    try:
        validate_account(two_step_session.account)
    except UnverifiedError as e:
        if not allow_unverified:
            raise e
    validate_session(two_step_session)
    await two_step_session.crosscheck_location(request)
    await two_step_session.crosscheck_code(request.form.get("code"))
    return two_step_session


async def verify_account(request: Request):
    """
    Removes the verification requirement from the account associated to an existing two-step session.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: code.

    Raises:
        SessionError

    Returns:
         two_step_session
    """
    two_step_session = await two_step_verification(request, True)
    two_step_session.account.verified = True
    await two_step_session.account.save(update_fields=["verified"])
    return two_step_session


def requires_two_step_verification():
    """
    Verifies a two-step challenge attempt.

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
            two_step_session = await two_step_verification(request)
            return await func(request, two_step_session, *args, **kwargs)

        return wrapped

    return wrapper
