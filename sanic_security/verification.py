import functools
from contextlib import suppress

from sanic.request import Request

from sanic_security.exceptions import (
    JWTDecodeError,
    NotFoundError,
    VerifiedError,
)
from sanic_security.models import (
    Account,
    TwoStepSession,
    CaptchaSession,
)

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


async def request_two_step_verification(
    request: Request, account: Account = None
) -> TwoStepSession:
    """
    Creates a two-step session and deactivates the client's current two-step session if found.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): email.
        account (Account): The account being associated with the new verification session. If None, an account is retrieved via the email in the request form-data or an existing two-step session.

    Raises:
        NotFoundError

    Returns:
         two_step_session
    """
    with suppress(NotFoundError, JWTDecodeError):
        two_step_session = await TwoStepSession.decode(request)
        if two_step_session.active:
            await two_step_session.deactivate()
        if not account:
            account = two_step_session.bearer
    if request.form.get("email") or not account:
        account = await Account.get_via_email(request.form.get("email"))
    two_step_session = await TwoStepSession.new(request, account)
    return two_step_session


async def two_step_verification(request: Request) -> TwoStepSession:
    """
    Validates a two-step verification attempt.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): code.

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        ChallengeError
        MaxedOutChallengeError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)
    two_step_session.validate()
    two_step_session.bearer.validate()
    await two_step_session.check_code(request, request.form.get("code"))
    return two_step_session


def requires_two_step_verification(arg=None):
    """
    Validates a two-step verification attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/verification/attempt")
            @requires_two_step_verification
            async def on_verified(request):
                response = json("Two-step verification attempt successful!", two_step_session.json())
                return response

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        ChallengeError
        MaxedOutChallengeError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.two_step_session = await two_step_verification(request)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator(arg) if callable(arg) else decorator


async def verify_account(request: Request) -> TwoStepSession:
    """
    Verifies the client's account via two-step session code.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): code.

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        ChallengeError
        MaxedOutChallengeError
        VerifiedError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)
    if two_step_session.bearer.verified:
        raise VerifiedError()
    two_step_session.validate()
    await two_step_session.check_code(request, request.form.get("code"))
    two_step_session.bearer.verified = True
    await two_step_session.bearer.save(update_fields=["verified"])
    return two_step_session


async def request_captcha(request: Request) -> CaptchaSession:
    """
    Creates a captcha session and deactivates the client's current captcha session if found.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        captcha_session
    """
    with suppress(NotFoundError, JWTDecodeError):
        captcha_session = await CaptchaSession.decode(request)
        if captcha_session.active:
            await captcha_session.deactivate()
    return await CaptchaSession.new(request)


async def captcha(request: Request) -> CaptchaSession:
    """
    Validates a captcha challenge attempt.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): captcha.

    Raises:
        DeletedError
        ExpiredError
        DeactivatedError
        JWTDecodeError
        NotFoundError
        ChallengeError
        MaxedOutChallengeError

    Returns:
        captcha_session
    """
    captcha_session = await CaptchaSession.decode(request)
    captcha_session.validate()
    await captcha_session.check_code(request, request.form.get("captcha"))
    return captcha_session


def requires_captcha(arg=None):
    """
    Validates a captcha challenge attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/captcha/attempt")
            @requires_captcha
            async def on_captcha_attempt(request):
                return json("Captcha attempt successful!", captcha_session.json())

    Raises:
        DeletedError
        ExpiredError
        DeactivatedError
        JWTDecodeError
        NotFoundError
        ChallengeError
        MaxedOutChallengeError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.captcha_session = await captcha(request)
            return await func(request, *args, **kwargs)

        return wrapper

    if callable(arg):
        return decorator(arg)
    else:
        return decorator
