import functools
from contextlib import suppress

from sanic import Request, Sanic

from sanic_security.exceptions import NotFoundError, JWTDecodeError

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


#async def request_captcha(request: Request) -> CaptchaSession:
async def request_captcha(request: Request):
    """
    Creates a captcha session and deactivates the client's current captcha session if found.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        captcha_session
    """
    _orm = Sanic.get_app().ctx.extensions['security']

    with suppress(NotFoundError, JWTDecodeError):
        captcha_session = await _orm.captcha_session.decode(request)
        if captcha_session.active:
            captcha_session.active = False
            await captcha_session.save(update_fields=["active"])
    return await _orm.captcha_session.new(request)


#async def captcha(request: Request) -> CaptchaSession:
async def captcha(request: Request):
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
    _orm = Sanic.get_app().ctx.extensions['security']

    captcha_session = await _orm.captcha_session.decode(request)
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
