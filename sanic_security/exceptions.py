from sanic.exceptions import SanicException

from sanic_security.utils import json


class SecurityError(SanicException):
    """
    Sanic Security related error.

    Attributes:
        response (HTTPResponse): Security Error json response.

    Args:
        message (str): Human readable error message.
        code (int): HTTP error code.
    """

    def __init__(self, message: str, code: int):
        self.response = json(message, self.__class__.__name__, code)
        super().__init__(message, code)


class NotFoundError(SecurityError):
    def __init__(self, message):
        super().__init__(message, 404)


class DeletedError(SecurityError):
    def __init__(self, message):
        super().__init__(message, 404)


class AccountError(SecurityError):
    def __init__(self, message, code):
        super().__init__(message, code)


class ExistsError(AccountError):
    def __init__(self):
        super().__init__("Account with this email or phone number already exists.", 409)


class DisabledError(AccountError):
    def __init__(self):
        super().__init__("This account has been disabled.", 401)


class PasswordIncorrectError(AccountError):
    def __init__(self):
        super().__init__("The password provided is incorrect.", 401)


class UnverifiedError(AccountError):
    def __init__(self):
        super().__init__("Account requires verification.", 401)


class SessionError(SecurityError):
    def __init__(self, message, code):
        super().__init__(message, code)


class DecodingError(SessionError):
    def __init__(self, exception):
        super().__init__(f"Session could not be decoded. {exception}", 400)


class InvalidError(SessionError):
    def __init__(self):
        super().__init__("Session is invalid.", 401)


class ExpiredError(SessionError):
    def __init__(self):
        super().__init__("Session has expired", 401)


class CrosscheckError(SessionError):
    def __init__(self, message="The code provided is incorrect."):
        super().__init__(message, 401)


class MaximumAttemptsError(SessionError):
    def __init__(self):
        super().__init__(
            "You've reached the maximum amount of attempts for this session.", 401
        )


class SecondFactorError(SessionError):
    def __init__(self):
        super().__init__("A second factor is required for this session.", 401)


class InsufficientRoleError(SecurityError):
    def __init__(self):
        super().__init__("Insufficient roles required for this action.", 403)


class InsufficientPermissionError(SecurityError):
    def __init__(self):
        super().__init__("Insufficient permissions required for this action.", 403)
