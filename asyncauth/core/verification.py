import functools

from sanic.request import Request

from asyncauth.core.models import Account, VerificationSession, CaptchaSession, SessionFactory

resources_path = './resources'
session_factory = SessionFactory()


async def request_verification(request: Request, account: Account):
    """
    Creates a verification session associated with an account. Renders account unverified.

    :param request: Sanic request parameter.

    :param account: The account that requires verification. If none, will retrieve account from verification or
    authentication session.

    :return: verification_session
    """
    if account.verified:
        account.verified = False
        await account.save(update_fields=['verified'])
    return await session_factory.get('verification', request, account=account)


async def verify_account(request: Request):
    """
    Verifies an account for use using a code sent via email or text.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :raises SessionError:

    :return: verification_session
    """
    verification_session = await VerificationSession().decode(request)
    VerificationSession.ErrorFactory(verification_session).throw()
    await verification_session.validate_code(request.form.get('code'))
    verification_session.valid = False
    verification_session.account.verified = True
    await verification_session.account.save(update_fields=['verified'])
    await verification_session.save(update_fields=['valid'])
    return verification_session


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    :param request: Sanic request parameter.

    :return: captcha_session
    """
    return await session_factory.get('captcha', request)


async def captcha(request: Request):
    """
    Validates captcha challenge attempt. Captcha is unusable after 1 incorrect attempt.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    captcha.

    :return: captcha_session
    """
    params = request.form
    captcha_session = await CaptchaSession().decode(request)
    CaptchaSession.ErrorFactory(captcha_session).throw()
    await captcha_session.validate_code( params.get('captcha'))
    captcha_session.valid = False
    await captcha_session.save(update_fields=['valid'])
    return captcha_session


def requires_captcha():
    """
    Has the same function as the captcha method, but is in the form of a decorator and authenticates client.

    :raises AccountError:

    :raises SessionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await captcha(request)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper
