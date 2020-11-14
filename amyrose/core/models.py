import random
import secrets
import string
import uuid

import jwt
from sanic.exceptions import ServerError
from tortoise import fields, Model

from amyrose import config_parser
from amyrose.core.utils import is_expired


class BaseModel(Model):
    id = fields.IntField(pk=True)
    uid = fields.UUIDField(default=uuid.uuid1, max_length=36)
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


class ErrorFactory:

    def get(self, model):
        raise NotImplementedError

    def raise_error(self, model):
        error = self.get(model)
        if error:
            raise error


class Account(BaseModel):
    username = fields.CharField(max_length=45)
    email = fields.CharField(unique=True, max_length=45)
    phone = fields.CharField(unique=True, max_length=20, null=True)
    password = fields.BinaryField()
    verified = fields.BooleanField(default=True)
    disabled = fields.BooleanField(default=False)

    class AccountExistsError(ServerError):
        def __init__(self):
            super().__init__('Account with this email or phone number already exists.', 409)

    class UnverifiedError(ServerError):
        def __init__(self):
            super().__init__("Account requires verification.", 401)

    class DisabledError(ServerError):
        def __init__(self):
            super().__init__("This account has been disabled.", 401)

    class IncorrectPasswordError(ServerError):
        def __init__(self):
            super().__init__('The password provided is incorrect.', 401)


class AccountErrorFactory(ErrorFactory):
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


class Session(BaseModel):
    expiration_date = fields.DatetimeField(null=True)
    valid = fields.BooleanField(default=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cookie_name = self.__class__.__name__[:4].lower() + 'tkn'

    def to_cookie(self):
        payload = {'uid': str(self.uid), 'parent_uid': str(self.parent_uid)}
        return jwt.encode(payload, config_parser['ROSE']['secret'], algorithm='HS256').decode('utf-8')

    @classmethod
    def from_cookie(cls, cookie_content):
        return jwt.decode(cookie_content, config_parser['ROSE']['secret'], 'utf-8', algorithms='HS256')


    class Meta:
        abstract = True

    class DecodeError(ServerError):
        def __init__(self):
            super().__init__("Session could not be decoded or cookie content is empty.", 500)

    class InvalidError(ServerError):
        def __init__(self):
            super().__init__("Session is invalid.", 403)

    class ExpiredError(ServerError):
        def __init__(self):
            super().__init__("Session has expired", 403)


class SessionErrorFactory(ErrorFactory):
    def get(self, model):
        error = None
        if model is None:
            error = Session.NotFoundError('Your session could not be found, please re-login and try again.')
        elif not model.valid:
            error = Session.InvalidError()
        elif is_expired(model.expiration_date):
            error = Session.ExpiredError()
        return error


class VerificationSession(Session):
    code = fields.CharField(unique=True, default=''.join(random.choices(string.ascii_letters + string.digits, k=9)),
                            max_length=9)

    class IncorrectCodeError(ServerError):
        def __init__(self):
            super().__init__('The code given does not match session code.')


class AuthenticationSession(Session):
    pass


class Role(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientRoleError(ServerError):
        def __init__(self):
            super().__init__('You do not have the required role for this action.', 403)


class Permission(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientPermissionsError(ServerError):
        def __init__(self):
            super().__init__('You do not have the required permissions for this action.', 403)
