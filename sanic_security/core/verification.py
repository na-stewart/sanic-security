import functools

from sanic.request import Request

from sanic_security.core.models import (
    Account,
    TwoStepSession,
    CaptchaSession,
    SessionFactory,
    SessionErrorFactory,
)

session_factory = SessionFactory()
session_error_factory = SessionErrorFactory()


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        captcha_session
    """
    return await session_factory.get("captcha", request)


async def captcha(request: Request):
    """
    Verifies a captcha challenge attempt.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: captcha.

    Raises:
        SessionError

    Returns:
        captcha_session
    """
    captcha_session = await CaptchaSession().decode(request)
    session_error_factory.throw(captcha_session)
    await captcha_session.crosscheck_code(request.form.get("captcha"))
    return captcha_session


def requires_captcha():
    """
    Verifies a captcha attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/captcha')
            @requires_captcha()
            async def on_captcha(request, captcha_session):
                return text('User has successfully completed the captcha challenge!')

    Raises:
        SessionError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            captcha_session = await captcha(request)
            return await func(request, captcha_session, *args, **kwargs)

        return wrapped

    return wrapper


async def request_two_step_verification(request: Request, account):
    """
    Creates a two-step session associated with an account.

    Args:
        request (Request): Sanic request parameter.
        account (Account): The account being associated with the verification session.

    Returns:
         two_step_session
    """
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
