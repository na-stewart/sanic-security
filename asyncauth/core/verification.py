import functools

from sanic.request import Request

from asyncauth.core.models import Account, VerificationSession, CaptchaSession, SessionFactory

session_factory = SessionFactory()


async def verify_account(verification_session: VerificationSession):
    """
    Verifies account associated to a verification session.

    :param verification_session: Verification session containing account being verified.
    """
    verification_session.account.verified = True
    await verification_session.account.save(update_fields=['verified'])


async def request_verification(request: Request, account: Account = None):
    """
    Creates a verification session associated with an account. Renders account unverified.

    :param request: Sanic request parameter.

    :param account: The account being associated with the verification session.

    :return: verification_session
    """
    return await session_factory.get('verification', request, account)


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    :param request: Sanic request parameter.

    :return: captcha_session
    """
    return await session_factory.get('captcha', request)


async def captcha(request: Request):
    """
    Enforces captcha.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    captcha.

    :raises SessionError:

    :return: captcha_session
    """
    captcha_session = await CaptchaSession().decode(request)
    CaptchaSession.ErrorFactory(captcha_session).throw()
    await captcha_session.crosscheck_code(request.form.get('captcha'))
    return captcha_session


async def verify(request: Request):
    """
    Enforces verification.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    code.

    :raises SessionError:

    :raises AccountError:

    :return: verification_session
    """
    verification_session = await VerificationSession().decode(request)
    VerificationSession.ErrorFactory(verification_session).throw()
    await verification_session.crosscheck_code(request.form.get('code'))
    return verification_session


def requires_captcha():
    """
    Enforced captcha.

    :raises AccountError:

    :raises SessionError:

    :return: await func(request, captcha_session, *args, **kwargs)
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            captcha_session = await captcha(request)
            return await func(request, captcha_session, *args, **kwargs)

        return wrapped

    return wrapper


def requires_verification():
    """
    Enforces verification.

    :raises AccountError:

    :raises SessionError:

    :return: func(request, verification_session, *args, **kwargs)
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            verification_session = await verify(request)
            return await func(request, verification_session, *args, **kwargs)

        return wrapped

    return wrapper
