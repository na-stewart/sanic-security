from sanic.exceptions import SanicException

from sanic_security.utils import json


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
        self.response = json(message, self.__class__.__name__, code)
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


class InvalidIdentifierError(AccountError):
    def __init__(self, message):
        super().__init__(message, 400)


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
        super().__init__(f"Session could not be decoded. {exception}", 400)


class InvalidError(SessionError):
    def __init__(self):
        super().__init__("Session is invalid.", 401)


class ExpiredError(SessionError):
    def __init__(self):
        super().__init__("Session has expired", 401)


class IncorrectCodeError(SessionError):
    def __init__(self):
        super().__init__("The code provided is incorrect.", 401)


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

class TwillioError(SanicException):
    pass
