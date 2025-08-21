import functools
from contextlib import suppress

from sanic.log import logger
from sanic.request import Request

from sanic_security.exceptions import (
    JWTDecodeError,
    NotFoundError,
    MaxedOutChallengeError,
    DeactivatedError,
)
from sanic_security.models import (
    Account,
    TwoStepSession,
    CaptchaSession,
)
from sanic_security.utils import get_ip

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
    request: Request, account: Account = None, tag: str = "2sv"
) -> TwoStepSession:
    """
    Creates a two-step session and deactivates the client's current two-step session if found.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): email.
        account (Account): The account being associated with the new verification session. If None, an account is retrieved via the email in the request form-data or an existing two-step session.
        tag (str): Label used to distinguish verification for specific purposes.

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
    two_step_session = await TwoStepSession.new(request, account, tag=tag)
    request.ctx.session = two_step_session
    return two_step_session


async def two_step_verification(request: Request, tag: str = "2sv") -> TwoStepSession:
    """
    Validates a two-step verification attempt.

    Args:
        request (Request): Sanic request parameter. Request body should contain form-data with the following argument(s): code.
        tag (str): Label used to distinguish verification for specific purposes.

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
    two_step_session = await TwoStepSession.decode(request, tag=tag)
    two_step_session.validate()
    two_step_session.bearer.validate()
    try:
        await two_step_session.check_code(request.form.get("code"))
    except MaxedOutChallengeError as e:
        logger.warning(
            f"Client {get_ip(request)} has exceeded maximum two-step session {two_step_session.id} challenge attempts."
        )
        raise e
    logger.info(
        f"Client {get_ip(request)} has completed two-step session {two_step_session.id} challenge."
    )
    return two_step_session


def requires_two_step_verification(func=None, *, tag="2sv"):
    """
    Validates a two-step verification attempt.

    Args:
        tag (str): Label used to distinguish verification for specific purposes.

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
            await two_step_verification(request, tag)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator if func is None else decorator(func)


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

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request, tag="2fa")
    if two_step_session.bearer.verified:
        raise DeactivatedError("Account already verified.", 403)
    two_step_session.validate()
    try:
        await two_step_session.check_code(request.form.get("code"))
    except MaxedOutChallengeError as e:
        logger.warning(
            f"Client {get_ip(request)} has exceeded maximum two-step session {two_step_session.id} challenge attempts "
            "during account verification."
        )
        raise e
    two_step_session.bearer.verified = True
    await two_step_session.bearer.save(update_fields=["verified"])
    logger.info(
        f"Client {get_ip(request)} has verified account {two_step_session.bearer.id}."
    )
    return two_step_session


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
    try:
        await captcha_session.check_code(request.form.get("captcha"))
    except MaxedOutChallengeError as e:
        logger.warning(
            f"Client {get_ip(request)} has exceeded maximum captcha session {captcha_session.id} challenge attempts."
        )
        raise e
    logger.info(
        f"Client {get_ip(request)} has completed captcha session {captcha_session.id} challenge."
    )
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
            await captcha(request)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator(arg) if callable(arg) else decorator
