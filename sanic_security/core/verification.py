import functools

from sanic.request import Request

from sanic_security.core.models import Account, TwoStepSession, CaptchaSession, SessionFactory, Session

session_factory = SessionFactory()
session_error_factory = Session.ErrorFactory()


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        captcha_session
    """
    return await session_factory.get('captcha', request)


async def captcha(request: Request):
    """
    Enforces A captcha to continue execution.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: captcha.

    Raises:
        SessionError

    Returns:
        captcha_session
    """
    captcha_session = await CaptchaSession().decode(request)
    session_error_factory.throw(captcha_session)
    await captcha_session.crosscheck_code(request.form.get('captcha'))
    return captcha_session


def requires_captcha():
    """
    Enforces A captcha to continue execution.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/captcha')
            @requires_captcha()
            async def on_captcha_successful(request, captcha_session):
                return text('User has successfully completed captcha challenge!')

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


async def request_two_step_verification(request: Request, account: Account = None):
    """
    Creates a verification session associated with an account.

    Args:
        request (Request): Sanic request parameter.
        account (Account): The account being associated with the verification session.

    Returns:
         two_step_session
    """
    if account is None:
        two_step_session = await TwoStepSession().decode(request)
        account = two_step_session.account
    return await session_factory.get('twostep', request, account=account)


async def verify_two_step_session(request: Request):
    """
    Enforces verification and validates attempts.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    code.

    :raises SessionError:

    :return: two_step_session
    """
    two_step_session = await TwoStepSession().decode(request)
    session_error_factory.throw(two_step_session)
    await two_step_session.crosscheck_code(request.form.get('code'))
    return two_step_session


async def verify_account(two_step_session: TwoStepSession):
    """
    Verifies account associated to a two step session.

    :param two_step_session: Verification session containing account being verified.
    """
    two_step_session.account.verified = True
    await two_step_session.account.save(update_fields=['verified'])
    return two_step_session


def requires_two_step_verification():
    """
    Enforces verification and validates attempts.

    :raises SessionError:

    :return: func(request, two_step_session, *args, **kwargs)
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            two_step_session = await verify_two_step_session(request)
            return await func(request, two_step_session, *args, **kwargs)

        return wrapped

    return wrapper
