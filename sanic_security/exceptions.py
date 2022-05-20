from sanic.exceptions import SanicException

from sanic_security.utils import json


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


class SecurityError(SanicException):
    """
    Sanic Security related error.

    Attributes:
        json_response (HTTPResponse): Security error json response.

    Args:
        message (str): Human readable error message.
        code (int): HTTP error code.
    """

    def __init__(self, message: str, code: int):
        self.json_response = json(message, self.__class__.__name__, code)
        super().__init__(message, code)


class NotFoundError(SecurityError):
    def __init__(self, message):
        super().__init__(message, 404)


class DeletedError(SecurityError):
    def __init__(self, message):
        super().__init__(message, 410)


class AccountError(SecurityError):
    def __init__(self, message, code):
        super().__init__(message, code)


class DisabledError(AccountError):
    def __init__(self):
        super().__init__("This account has been disabled.", 401)


class UnverifiedError(AccountError):
    def __init__(self):
        super().__init__("Account requires verification.", 401)


class SessionError(SecurityError):
    def __init__(self, message, code=401):
        super().__init__(message, code)


class JWTDecodeError(SessionError):
    def __init__(self, message):
        super().__init__(message, 400)


class DeactivatedError(SessionError):
    def __init__(self, message="Session is deactivated."):
        super().__init__(message, 401)


class ExpiredError(SessionError):
    def __init__(self):
        super().__init__("Session has expired", 401)


class ChallengeError(SessionError):
    def __init__(self, message):
        super().__init__(message, 401)


class MaxedOutChallengeError(ChallengeError):
    def __init__(self):
        super().__init__("The maximum amount of attempts has been reached.")


class AuthorizationError(SecurityError):
    def __init__(self, message):
        super().__init__(message, 403)


class CredentialsError(SecurityError):
    def __init__(self, message, code=400):
        super().__init__(message, code)
