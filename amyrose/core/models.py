import random
import string
import uuid

import jwt
from jwt import DecodeError
from sanic.exceptions import ServerError
from sanic.request import Request
from sanic.response import HTTPResponse
from tortoise import fields, Model

from amyrose.core.config import config_parser
from amyrose.core.utils import is_expired, best_by


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


class RoseError(ServerError):
    def __init__(self, message, code):
        super().__init__(message, code)


class EmptyEntryError(RoseError):
    def __init__(self, message):
        super().__init__(message, 400)


class BaseModel(Model):
    id = fields.IntField(pk=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    parent_uid = fields.UUIDField(null=True, max_length=36)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    class Meta:
        abstract = True

    class NotFoundError(RoseError):
        def __init__(self, message):
            super().__init__(message, 404)

    class DeletedError(RoseError):
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

    class AccountError(RoseError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class AccountExistsError(AccountError):
        def __init__(self):
            super().__init__('Account with this email or phone number already exists.', 409)

    class InvalidEmailError(AccountError):
        def __init__(self):
            super().__init__('Please use a valid email format such as you@mail.com.', 400)

    class DisabledError(AccountError):
        def __init__(self):
            super().__init__("This account has been disabled. This could be due to an infraction.", 401)

    class IncorrectPasswordError(AccountError):
        def __init__(self):
            super().__init__('The password provided is incorrect.', 401)

    class UnverifiedError(AccountError):
        def __init__(self):
            super().__init__('Account requires verification.', 401)


class Session(BaseModel):
    expiration_date = fields.DatetimeField(default=best_by, null=True)
    valid = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)

    def cookie_name(self):
        """
        The name of the cookie that stores the session's jwt.

        :return: cookie_name
        """
        return self.__class__.__name__[:4].lower() + 'tkn'

    def encode(self, response: HTTPResponse, secure: bool = False, same_site: str = 'lax'):
        """
        Transforms session into jwt and then is stored in a cookie.

        :param response: Response used to store cookie.

        :param secure: If true, connections must be SSL encrypted (aka https).

        :param same_site: Allows you to declare if your cookie should be restricted to a first-party or same-site context.
        """

        payload = {'uid': str(self.uid), 'parent_uid': str(self.parent_uid), 'ip': self.ip}
        encoded = jwt.encode(payload, config_parser['ROSE']['secret'], algorithm='HS256').decode('utf-8')
        cookie_name = self.cookie_name()
        response.cookies[cookie_name] = encoded
        response.cookies[cookie_name]['expires'] = self.expiration_date
        response.cookies[cookie_name]['secure'] = secure
        response.cookies[cookie_name]['samesite'] = same_site

    async def decode(self, request: Request, raw=False):
        """
        Transforms jwt token retrieved from cookie into a session.

        :param raw: If true, request database for the session and return. If false, return raw cookie data as dict.

        :param request: Sanic request parameter.

        :return: session
        """
        try:
            decoded = jwt.decode(request.cookies.get(self.cookie_name()), config_parser['ROSE']['secret'], 'utf-8',
                                 algorithms='HS256')
            session = decoded if raw else await self.filter(uid=decoded['uid']).first()
            return session
        except DecodeError:
            raise Session.DecodeError(self.__class__.__name__)

    class Meta:
        abstract = True

    class ErrorFactory(BaseErrorFactory):
        def get(self, model):
            error = None
            if model is None:
                error = Session.NotFoundError('Your session could not be found, please re-login and try again.')
            elif not model.valid:
                error = Session.InvalidError(model.__class__.__name__)
            elif model.deleted:
                error = Session.DeletedError(model.__class__.__name__ + ' has been deleted.')
            elif is_expired(model.expiration_date):
                error = Session.ExpiredError(model.__class__.__name__)
            return error

    class SessionError(RoseError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class DecodeError(SessionError):
        def __init__(self, name):
            super().__init__(name + " requested could not be decoded due to an error or cookie is non existent.", 401)

    class InvalidError(SessionError):
        def __init__(self, name):
            super().__init__(name + " is invalid.", 401)

    class ExpiredError(SessionError):
        def __init__(self, name):
            super().__init__(name + " has expired", 401)

    class UnknownLocationError(SessionError):
        def __init__(self):
            super().__init__("No session with client ip has been found. Location unknown.", 401)


class VerificationSession(Session):
    code = fields.CharField(unique=True, max_length=7)

    class VerificationAttemptError(Session.SessionError):
        def __init__(self):
            super().__init__('The code given does not match session code.', 401)

    class VerificationPendingError(Session.SessionError):
        def __init__(self):
            super().__init__('A verification session for this account is pending.', 401)


class CaptchaSession(Session):
    challenge = fields.CharField(max_length=5)
    attempts = fields.IntField(default=0, max_length=1)

    class IncorrectAttemptError(Session.SessionError):
        def __init__(self):
            super().__init__('Your captcha attempt was incorrect. Please try again or refresh.', 401)

    class MaximumAttemptsError(Session.SessionError):
        def __init__(self):
            super().__init__('The maximum amount of incorrect attempts have been reached for this captcha. '
                             'Captcha has been invalidated.', 401)


class AuthenticationSession(Session):
    pass


class Role(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientRoleError(RoseError):
        def __init__(self):
            super().__init__('You do not have the required role for this action.', 403)


class Permission(BaseModel):
    name = fields.CharField(max_length=45)

    class InsufficientPermissionError(RoseError):
        def __init__(self):
            super().__init__('You do not have the required permissions for this action.', 403)
