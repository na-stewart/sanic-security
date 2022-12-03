import functools
from contextlib import suppress

from sanic.request import Request

from sanic_security.exceptions import (
    AccountError,
    JWTDecodeError,
    NotFoundError,
)
from sanic_security.models import (
    Account,
    TwoStepSession,
    CaptchaSession,
)

"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2020-present Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


async def request_two_step_verification(
    request: Request, account: Account = None
) -> TwoStepSession:
    """
    Creates a two-step session and deactivates the client's current two-step session if found.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: email.
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
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: code.

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


async def verify_account(request: Request) -> TwoStepSession:
    """
    Verifies account via two-step session code.

    Args:
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: code.

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        ChallengeError
        MaxedOutChallengeError
        AccountError

    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)
    if two_step_session.bearer.verified:
        raise AccountError("Account already verified.", 403)
    two_step_session.validate()
    await two_step_session.check_code(request, request.form.get("code"))
    two_step_session.bearer.verified = True
    await two_step_session.bearer.save(update_fields=["verified"])
    return two_step_session


def requires_two_step_verification():
    """
    Validates a two-step verification attempt.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/verification/attempt")
            @requires_two_step_verification()
            async def on_verified(request, two_step_session):
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

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            two_step_session = await two_step_verification(request)
            return await func(request, two_step_session, *args, **kwargs)

        return wrapped

    return wrapper


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
        request (Request): Sanic request parameter. All request bodies are sent as form-data with the following arguments: captcha.

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
        DeletedError
        ExpiredError
        DeactivatedError
        JWTDecodeError
        NotFoundError
        ChallengeError
        MaxedOutChallengeError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            captcha_session = await captcha(request)
            return await func(request, captcha_session, *args, **kwargs)

        return wrapped

    return wrapper
