import functools

from sanic import Request

from sanic_security.models import CaptchaSession, SessionFactory
from sanic_security.validation import validate_session

session_factory = SessionFactory()


async def request_captcha(request: Request):
    """
    Creates a captcha session.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        captcha_session
    """
    return await session_factory.get("captcha", request)


async def captcha(request: Request):
    """
    Validates a captcha challenge attempt.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: captcha.

    Raises:
        SessionError

    Returns:
        captcha_session
    """
    captcha_session = await CaptchaSession.decode(request)
    validate_session(captcha_session)
    await captcha_session.crosscheck_code(request.form.get("captcha"))
    return captcha_session


def requires_captcha():
    """
    Validates a captcha challenge attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/captcha/attempt")
            @requires_captcha()
            async def on_captcha_attempt(request, captcha_session):
                return json("Captcha attempt successful!", captcha_session.json())
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
