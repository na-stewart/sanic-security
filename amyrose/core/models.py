import random
import secrets
import string
import uuid

from sanic.exceptions import ServerError, ServerError, ServerError
from tortoise import fields, Model

from amyrose.core.utils import is_expired


class BaseModel(Model):
    id = fields.IntField(pk=True)
    uid = fields.UUIDField(default=uuid.uuid1, null=False)
    parent_uid = fields.UUIDField(null=True)
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


class AuthenticationError(ServerError):
    def __init__(self, message, status_code):
        super().__init__(message, status_code)


class AuthorizationError(ServerError):
    def __init__(self, message, status_code):
        super().__init__(message, status_code)


class InsufficientPermissionsError(ServerError):
    def __init__(self, message, status_code):
        super().__init__(message, status_code)


class InsufficientRoleError(ServerError):
    def __init__(self, message, status_code):
        super().__init__(message, status_code)


class IncorrectPasswordError(AuthenticationError):
    def __init__(self):
        super().__init__('The password provided is incorrect.', 401)


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
    password = fields.BinaryField(null=False)
    verified = fields.BooleanField(default=False)
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
    token = fields.CharField(default=secrets.token_hex(32), max_length=64)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.token_name = self.__class__.__name__[:4].lower() + 'tkn'

    class InvalidError(ServerError):
        def __init__(self):
            super().__init__("Session is invalid.", 403)

    class ExpiredError(ServerError):
        def __init__(self):
            super().__init__("Session has expired", 403)

    class SessionDecodeError(ServerError):
        def __init__(self):
            super().__init__('Session could not be decoded. You may need to re-login.', 500)

    class SessionEncodeError(ServerError):
        def __init__(self):
            super().__init__('Session could not be encoded. Make sure secret has been defined in config.', 500)


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

    class InvalidCodeError(Session.InvalidError):
        def __init__(self):
            super('The code given does not match session code.', 403)


class AuthenticationSession(Session):
    pass


class Role(BaseModel):
    name = fields.CharField(max_length=45, null=False)


class Permission(BaseModel):
    name = fields.CharField(max_length=45, null=False)
