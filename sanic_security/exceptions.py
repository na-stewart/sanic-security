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
    """
    Raised when a resource cannot be found.
    """

    def __init__(self, message):
        super().__init__(message, 404)


class DeletedError(SecurityError):
    """
    Raised when attempting to access a deleted resource.
    """

    def __init__(self, message):
        super().__init__(message, 410)


class AccountError(SecurityError):
    """
    Base account error that all other account errors derive from.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class DisabledError(AccountError):
    """
    Raised when account is disabled.
    """

    def __init__(self, message: str = "Account is disabled.", code: int = 401):
        super().__init__(message, code)


class UnverifiedError(AccountError):
    """
    Raised when account is unverified.
    """

    def __init__(self):
        super().__init__("Account requires verification.", 401)


class VerifiedError(AccountError):
    """
    Raised when account is already verified.
    """

    def __init__(self):
        super().__init__("Account already verified.", 403)


class SessionError(SecurityError):
    """
    Base session error that all other session errors derive from.
    """

    def __init__(self, message, code=401):
        super().__init__(message, code)


class JWTDecodeError(SessionError):
    """
    Raised when client JWT is invalid.
    """

    def __init__(self, message):
        super().__init__(message, 400)


class DeactivatedError(SessionError):
    """
    Raised when session is deactivated.
    """

    def __init__(self, message: str = "Session is deactivated.", code: int = 401):
        super().__init__(message, code)


class ExpiredError(SessionError):
    """
    Raised when session has expired.
    """

    def __init__(self):
        super().__init__("Session has expired")


class SecondFactorRequiredError(SessionError):
    """
    Raised when authentication session two-factor requirement isn't met.
    """

    def __init__(self):
        super().__init__("Session requires second factor for authentication.")


class SecondFactorFulfilledError(SessionError):
    """
    Raised when authentication session two-factor requirement is already met.
    """

    def __init__(self):
        super().__init__("Session second factor requirement already met.", 403)


class ChallengeError(SessionError):
    """
    Raised when a session challenge attempt is invalid.
    """

    def __init__(self, message):
        super().__init__(message)


class MaxedOutChallengeError(ChallengeError):
    """
    Raised when a session's challenge attempt limit is reached.
    """

    def __init__(self):
        super().__init__("The maximum amount of attempts has been reached.")


class AuthorizationError(SecurityError):
    """
    Raised when an account has insufficient permissions or roles for an action.
    """

    def __init__(self, message):
        super().__init__(message, 403)


class CredentialsError(SecurityError):
    """
    Raised when credentials are invalid.
    """

    def __init__(self, message, code=400):
        super().__init__(message, code)
