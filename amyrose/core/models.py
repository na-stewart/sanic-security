import inspect
import random
import string
import uuid

import jwt
from jwt import DecodeError
from sanic.exceptions import ServerError
from tortoise import fields, Model

from amyrose.core.config import config_parser
from amyrose.core.utils import is_expired


class BaseErrorFactory:
    """
    Easily raise or retrieve errors based off of variable values.
    """

    def get(self, model):
        """
        Retrieves an error if certain conditions are met.

        :return: error
        """
        raise NotImplementedError()

    def raise_error(self, model):
        error = self.get(model)
        if error:
            raise error


class BaseModel(Model):
    id = fields.IntField(pk=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    parent_uid = fields.UUIDField(null=True, max_length=36)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    class Meta:
        abstract = True

    class NotFoundError(ServerError):
        def __init__(self, message):
            super().__init__(message, 404)

    class DeletedError(ServerError):
        def __init__(self, message):
            super().__init__(message, 404)


class Account(BaseModel):
    username = fields.CharField(max_length=45)
    email = fields.CharField(unique=True, max_length=45)
    phone = fields.CharField(unique=True, max_length=20, null=True)
    password = fields.BinaryField()
    disabled = fields.BooleanField(default=False)
    verified = fields.BooleanField(default=False)

    class ErrorFactory(BaseErrorFactory):
        def get(self, model):
            error = None
            if not model:
                error = Account.NotFoundError('This account does not exist.')
            elif model.deleted:
                error = Account.DeletedError('This account has been permanently deleted.')
            elif model.disabled:
                error = Account.DisabledError()
            elif not model.verified:
                error = Account.UnverifiedError()
            return error

    class AccountError(ServerError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class AccountExistsError(AccountError):
        def __init__(self):
            super().__init__('Account with this email or phone number already exists.', 409)

    class DisabledError(AccountError):
        def __init__(self):
            super().__init__("This account has been disabled.", 401)

    class IncorrectPasswordError(AccountError):
        def __init__(self):
            super().__init__('The password provided is incorrect.', 401)

    class UnverifiedError(AccountError):
        def __init__(self):
            super().__init__('This account is unverified.', 401)


class Session(BaseModel):
    expiration_date = fields.DatetimeField(null=True)
    valid = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)

    def cookie_name(self):
        """
        The name of the cookie that stores the session's jwt.

        :return: cookie_name
        """
        return self.__class__.__name__[:4].lower() + 'tkn'

    def to_cookie(self):
        """
        Transforms session into a jwt to be stored as a cookie.

        :return: jwt
        """
        payload = {'uid': str(self.uid), 'parent_uid': str(self.parent_uid), 'ip': self.ip}
        return jwt.encode(payload, config_parser['ROSE']['secret'], algorithm='HS256').decode('utf-8')

    @classmethod
    def from_cookie(cls, cookie_content):
        """
        Transforms jwt token retrieved from cookie into a readable payload dictionary.

        :return: payload
        """
        try:
            return jwt.decode(cookie_content, config_parser['ROSE']['secret'], 'utf-8', algorithms='HS256')
        except DecodeError:
            raise Session.DecodeError()

    class Meta:
        abstract = True

    class ErrorFactory(BaseErrorFactory):
        async def get(self, model):
            error = None
            if model is None:
                error = Session.NotFoundError('Your session could not be found, please re-login and try again.')
            elif not model.valid:
                error = Session.InvalidError()
            elif model.deleted:
                error = Session.DeletedError('Your session has been deleted.')
            elif is_expired(model.expiration_date):
                error = Session.ExpiredError()
            return error

    class SessionError(ServerError):
        def __init__(self, message, code):
            super.__init__(message, code)

    class DecodeError(SessionError):
        def __init__(self):
            super().__init__("Session requested could not be decoded due to an error or cookie is non existent.", 401)

    class InvalidError(SessionError):
        def __init__(self):
            super().__init__("Session is invalid.", 401)

    class ExpiredError(SessionError):
        def __init__(self):
            super().__init__("Session has expired", 401)

    class UnknownLocationError(SessionError):
        def __init__(self):
            super().__init__("No session with client ip has been found. Location unknown.", 401)


class VerificationSession(Session):
    code = fields.CharField(unique=True, default=''.join(random.choices(string.digits, k=7)), max_length=7)

    class IncorrectCodeError(Session.SessionError):
        def __init__(self):
            super().__init__('The code given does not match session code.', 401)

    class VerificationPendingError(Session.SessionError):
        def __init__(self):
            super().__init__('A verification session for this account is pending.', 401)


class AuthenticationSession(Session):
    pass


class Role(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientRoleError(ServerError):
        def __init__(self):
            super().__init__('You do not have the required role for this action.', 403)


class Permission(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientPermissionError(ServerError):
        def __init__(self):
            super().__init__('You do not have the required permissions for this action.', 403)
