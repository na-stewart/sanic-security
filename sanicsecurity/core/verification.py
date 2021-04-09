import functools

from sanic.request import Request

from sanicsecurity.core.models import Account, VerificationSession, CaptchaSession, SessionFactory, Session

session_factory = SessionFactory()
session_error_factory = Session.ErrorFactory()


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
    session_error_factory.throw(captcha_session)
    await captcha_session.crosscheck_code(request.form.get('captcha'))
    return captcha_session


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


async def request_verification(request: Request, account: Account = None):
    """
    Creates a verification session associated with an account. Renders account unverified.

    :param request: Sanic request parameter.

    :param account: The account being associated with the verification session.

    :return: verification_session
    """
    if account is None:
        verification_session = await VerificationSession().decode(request)
        account = verification_session.account
    return await session_factory.get('verification', request, account=account)


async def verify(request: Request, verification_type: str = None):
    """
    Enforces verification.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    code.

    :raises SessionError:

    :raises AccountError:

    :return: verification_session
    """
    verification_session = await VerificationSession(verification_type=verification_type).decode(request)
    session_error_factory.throw(verification_session)
    await verification_session.crosscheck_code(request.form.get('code'))
    return verification_session


async def verify_account(request: Request):
    """
    Verifies account associated to a verification session.

    :param request: Sanic request paramater. All request bodies are sent as form-data with the following arguments:
    code.
    """
    verification_session = await verify(request, 'account')
    verification_session.account.verified = True
    await verification_session.account.save(update_fields=['verified'])
    return verification_session


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
