import os
import random
import uuid

import aiofiles
import jwt
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic.exceptions import ServerError
from sanic.request import Request
from sanic.response import HTTPResponse
from tortoise import fields, Model

from asyncauth.core.config import config
from asyncauth.core.utils import is_expired, best_by, request_ip, random_str, str_to_list, hash_password


class BaseErrorFactory:
    """
    Easily raise or retrieve errors based off of variable values.
    """

    def __init__(self, model):
        self.error = self.get(model)

    def get(self, model):
        """
        Retrieves an error if certain conditions are met.
        :return: error
        """
        raise NotImplementedError()

    def throw(self):
        """
        Retrieves an error and raises it if certain conditions are met.
        :return: error
        """
        if self.error:
            raise self.error


class RoseError(ServerError):
    """
    Amyrose specific error.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class BaseModel(Model):
    id = fields.IntField(pk=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    def json(self):
        raise NotImplementedError()

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

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'email': self.email,
            'username': self.username,
            'disabled': self.disabled,
            'verified': self.verified
        }

    @staticmethod
    async def get_client(request: Request):
        """
        Retrieves account information from an authentication session found within cookie.
        :param request: Sanic request parameter.
        :return: account
        """

        authentication_session = await AuthenticationSession().decode(request)
        return authentication_session.account

    class AccountError(RoseError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class ExistsError(AccountError):
        def __init__(self):
            super().__init__('Account with this email or phone number already exists.', 409)

    class TooManyCharsError(AccountError):
        def __init__(self):
            super().__init__('Email, username, or phone number is too long.', 400)

    class InvalidEmailError(AccountError):
        def __init__(self):
            super().__init__('Please use a valid email format such as you@mail.com.', 400)

    class DisabledError(AccountError):
        def __init__(self):
            super().__init__("This account has been disabled.", 403)

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
    code = fields.CharField(max_length=6, null=True)
    account = fields.ForeignKeyField('models.Account', null=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cookie = self.__class__.__name__[:4].lower() + 'tkn'

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'expiration_date': str(self.expiration_date),
            'valid': self.valid,
            'ip': self.ip
        }

    def encode(self, response: HTTPResponse, secure: bool = False, same_site: str = 'lax'):
        """
        Transforms session into jwt and then is stored in a cookie.

        :param response: Response used to store cookie.

        :param secure: If true, connections must be SSL encrypted (aka https).

        :param same_site: Allows you to declare if your cookie should be restricted to a first-party or same-site context.
        """

        payload = {
            'date_created': str(self.date_created),
            'uid': str(self.uid),
            'ip': self.ip
        }
        encoded = jwt.encode(payload, config['AUTH']['secret'], algorithm='HS256')
        response.cookies[self.cookie] = encoded
        response.cookies[self.cookie]['expires'] = self.expiration_date
        response.cookies[self.cookie]['secure'] = secure
        response.cookies[self.cookie]['samesite'] = same_site

    def decode_raw(self, request: Request) -> dict:
        """
        Decodes JWT token in cookie to dict.

        :param request: Sanic request parameter.

        :return: raw
        """
        try:
            session = jwt.decode(request.cookies.get(self.cookie), config['AUTH']['secret'], algorithms='HS256')
            return session
        except DecodeError:
            raise Session.DecodeError()

    async def decode(self, request: Request):
        """
        Decodes JWT token in cookie and transforms into session.

        :param request: Sanic request parameter.

        :return: session
        """
        decoded = self.decode_raw(request)
        return await self.filter(uid=decoded.get('uid')).prefetch_related('account').first()

    class Meta:
        abstract = True

    class ErrorFactory(BaseErrorFactory):
        def get(self, model):
            error = None
            if model is None:
                error = Session.NotFoundError('Session could not be found.')
            elif not model.valid:
                error = Session.InvalidError()
            elif model.deleted:
                error = Session.DeletedError('Session has been deleted.')
            elif is_expired(model.expiration_date):
                error = Session.ExpiredError()
            return error

    class SessionError(RoseError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class DecodeError(SessionError):
        def __init__(self):
            super().__init__('Session is not available.', 401)

    class InvalidError(SessionError):
        def __init__(self):
            super().__init__('Session is invalid.', 401)

    class ExpiredError(SessionError):
        def __init__(self):
            super().__init__('Session has expired', 401)


class SessionFactory:

    def __init__(self):
        self.path = './resources/scache'

    async def generate_session_codes(self):
        """
        Generates up to 100 verification code variations in a codes.txt file
        """
        if not os.path.exists(self.path):
            os.makedirs(self.path)
            async with aiofiles.open(self.path + '/codes.txt', mode="w") as f:
                image = ImageCaptcha(fonts=str_to_list(config['AUTH']['captcha_fonts']))
                for i in range(100):
                    code = random_str(6)
                    await f.write(code + ' ')
                    image.write(code, self.path + '/' + code + '.png')

    async def _get_random_code(self):
        """
        Retrieves a random code from a codes.txt file

        :return: code
        """
        async with aiofiles.open(self.path + '/codes.txt', mode='r') as f:
            codes = await f.read()
            return random.choice(codes.split())

    async def get(self, session_type: str, request: Request, account : Account):
        await self.generate_session_codes()
        code = await self._get_random_code()
        if session_type == 'captcha':
            return await CaptchaSession.create(ip=request_ip(request), code=code)
        elif session_type == 'verification':
            return await VerificationSession.create(code=code, ip=request_ip(request), account=account)
        elif session_type == 'authentication':
            return await AuthenticationSession.create(account=account, ip=request_ip(request),
                                                      expiration_date=best_by(30))
        elif session_type == 'recovery':
            return await RecoverySession.create(account=account, ip=request_ip(request), code=code)
        else:
            raise ValueError


class VerificationSession(Session):
    class VerificationCodeError(Session.SessionError):
        def __init__(self):
            super().__init__('Your verification attempt was incorrect', 403)


class RecoverySession(VerificationSession):
    pass


class CaptchaSession(Session):
    attempts = fields.IntField(default=0, max_length=1)

    class IncorrectCaptchaError(Session.SessionError):
        def __init__(self):
            super().__init__('Your captcha attempt was incorrect.', 403)

    async def captcha_img(self, request):
        """
        Retrieves image path of client captcha.

        :return: captcha_img_path
        """
        decoded_captcha_session = self.decode_raw(request)
        captcha_session = await CaptchaSession.filter(uid=decoded_captcha_session.get('uid')).first()
        return './resources/scache/' + captcha_session.code + '.png'


class AuthenticationSession(Session):
    class UnknownLocationError(Session.SessionError):
        def __init__(self):
            super().__init__('Attempting to authenticate in an unknown location.', 403)

    async def verify_location(self, request):
        """
        Checks if client using session is in a known location (ip address). Prevents cookie jacking.

        :raises UnknownLocationError:
        """

        if not await AuthenticationSession.filter(ip=request_ip(request), account=self.account).exists():
            raise AuthenticationSession.UnknownLocationError()


class AuthorizationCredential(BaseModel):
    account = fields.ForeignKeyField('models.Account')
    description = fields.TextField(null=True)

    def json(self):
        raise NotImplementedError

    class Meta:
        abstract = True


class Role(AuthorizationCredential):
    name = fields.CharField(max_length=45)

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'name': self.name,
            'description': self.description
        }

    class InsufficientRoleError(RoseError):
        def __init__(self):
            super().__init__('You do not have the required role for this action.', 403)


class Permission(AuthorizationCredential):
    wildcard = fields.CharField(max_length=45)

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'wildcard': self.wildcard,
            'description': self.description
        }

    class InsufficientPermissionError(RoseError):
        def __init__(self):
            super().__init__('You do not have the required permissions for this action.', 403)
