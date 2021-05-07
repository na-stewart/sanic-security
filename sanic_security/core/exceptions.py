from sanic.exceptions import SanicException
from sanic.response import json


class SecurityError(SanicException):
    """
    Sanic Security related error.

    Attributes:
        response (HTTPResponse): Security Error json response.

    Args:
        message (str): Human readable error message.
        code (int): HTTP Error code.
    """

    def __init__(self, message: str, code: int):
        self.response = json(
            {
                "message": "An error has occurred!",
                "error_code": code,
                "data": {"error": self.__class__.__name__, "summary": message},
            },
            status=code,
        )
        super().__init__(message, code)


class NotFoundError(SecurityError):
    """
    Raised when a model can't be found in the database.
    Args:
        message (str): Human readable error message.
    """

    def __init__(self, message):
        super().__init__(message, 404)


class DeletedError(SecurityError):
    """
    Raised when a model in the database has been marked deleted.
    Args:
        message (str): Human readable error message.
    """

    def __init__(self, message):
        super().__init__(message, 404)


class AccountError(SecurityError):
    """
    An account related error.

    Args:
        message (str): Human readable error message.
        code (int): HTTP Error code.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class ExistsError(AccountError):
    def __init__(self):
        super().__init__("Account with this email or phone number already exists.", 409)


class TooManyCharsError(AccountError):
    def __init__(self):
        super().__init__("Email, username, or phone number is too long.", 400)


class InvalidEmailError(AccountError):
    def __init__(self):
        super().__init__("Please use a valid email format such as you@mail.com.", 400)


class DisabledError(AccountError):
    def __init__(self):
        super().__init__("This account has been disabled.", 401)


class PasswordMismatchError(AccountError):
    def __init__(self):
        super().__init__("The password provided does not match account password.", 401)


class UnverifiedError(AccountError):
    def __init__(self):
        super().__init__("Account requires verification.", 401)


class SessionError(SecurityError):
    """
    A session related error.

    Args:
        message (str): Human readable error message.
        code (int): HTTP Error code.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class DecodingError(SessionError):
    def __init__(self, exception):
        super().__init__("Session cookie could not be decoded. " + str(exception), 400)


class InvalidError(SessionError):
    def __init__(self):
        super().__init__("Session is invalid.", 401)


class ExpiredError(SessionError):
    def __init__(self):
        super().__init__("Session has expired", 401)


class CrosscheckError(SessionError):
    def __init__(self):
        super().__init__("Session crosschecking attempt was incorrect", 401)


class MaximumAttemptsError(SessionError):
    def __init__(self):
        super().__init__(
            "You've reached the maximum amount of attempts for this session.", 401
        )


class UnknownLocationError(SessionError):
    def __init__(self):
        super().__init__("Session in an unknown location.", 401)


class InsufficientRoleError(SecurityError):
    def __init__(self):
        super().__init__("Insufficient roles required for this action.", 403)


class InsufficientPermissionError(SecurityError):
    def __init__(self):
        super().__init__("Insufficient permissions required for this action.", 403)
