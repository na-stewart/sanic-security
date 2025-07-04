from sanic.exceptions import SanicException

from sanic_security.utils import json

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


class SecurityError(SanicException):
    """
    Sanic Security related error.

    Attributes:
        json (HTTPResponse): Security error json response.

    Args:
        message (str): Human readable error message.
        code (int): HTTP error code.
    """

    def __init__(self, message: str, code: int):
        self.json = json(message, self.__class__.__name__, code)
        super().__init__(message, code)


class NotFoundError(SecurityError):
    """Raised when a resource cannot be found on the database."""

    def __init__(self, message):
        super().__init__(message, 404)


class DeletedError(SecurityError):
    """Raised when attempting to access a resource marked as deleted."""

    def __init__(self, message):
        super().__init__(message, 404)


class CredentialsError(SecurityError):
    """Raised when credentials are invalid."""

    def __init__(self, message, code=400):
        super().__init__(message, code)


class OAuthError(SecurityError):
    """Raised when an error occurs during OAuth flow."""

    def __init__(self, message, code=401):
        super().__init__(message, code)


class AccountError(SecurityError):
    """Base account error that all other account errors derive from."""

    def __init__(self, message, code):
        super().__init__(message, code)


class DisabledError(AccountError):
    """Raised when account is disabled."""

    def __init__(self, message: str = "Account is disabled.", code: int = 401):
        super().__init__(message, code)


class UnverifiedError(AccountError):
    """Raised when account is unverified."""

    def __init__(self):
        super().__init__("Account requires verification.", 401)


class SessionError(SecurityError):
    """Base session error that all other session errors derive from."""

    def __init__(self, message, code=401):
        super().__init__(message, code)


class JWTDecodeError(SessionError):
    """Raised when client JWT is invalid."""

    def __init__(
        self, message="Session token invalid, not provided, or expired.", code=401
    ):
        super().__init__(message, code)


class DeactivatedError(SessionError):
    """Raised when session is deactivated."""

    def __init__(
        self,
        message: str = "Session has been deactivated.",
        code: int = 401,
    ):
        super().__init__(message, code)


class ExpiredError(SessionError):
    """Raised when session has expired."""

    def __init__(self, message="Session has expired."):
        super().__init__(message)


class SecondFactorRequiredError(SessionError):
    """Raised when authentication session two-factor requirement isn't met."""

    def __init__(self):
        super().__init__("Session requires second factor for authentication.")


class ChallengeError(SessionError):
    """Raised when a session challenge attempt is invalid."""

    def __init__(self, message):
        super().__init__(message)


class MaxedOutChallengeError(ChallengeError):
    """Raised when a session's challenge attempt limit is reached."""

    def __init__(self):
        super().__init__("The maximum amount of attempts has been reached.")


class AuthorizationError(SecurityError):
    """Raised when an account has insufficient permissions or roles for an action."""

    def __init__(self, message):
        super().__init__(message, 403)


class AnonymousError(AuthorizationError):
    """Raised when attempting to authorize an anonymous user."""

    def __init__(self):
        super().__init__("Session is anonymous.")


class AuditWarning(Warning):
    """Raised when configuration may be dangerous."""
