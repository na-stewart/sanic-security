import asyncio
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
from asyncauth.core.utils import is_expired, best_by, request_ip, random_str, path_exists, str_to_list
from asyncauth.lib.smtp import send_email
from asyncauth.lib.twilio import send_sms


class BaseErrorFactory:
    """
    Easily raise or retrieve errors based off of variable values.
    """

    def __init__(self, model):
        self.model = model

    def get(self):
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
        error = self.get()
        if error:
            raise error


class AuthError(ServerError):
    """
    Base error for all asyncauth related errors.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class BaseModel(Model):
    """
    Base asyncauth model that all other models derive from. Some important elements to take in consideration is that
    deletion should be done via the 'deleted' variable and filtering it out rather than completely removing it from
    the database. Retrieving asyncauth models should be done via filtering with the 'uid' variable rather then the id
    variable.
    """

    id = fields.IntField(pk=True)
    account = fields.ForeignKeyField('models.Account', null=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    def json(self):
        raise NotImplementedError()

    class Meta:
        abstract = True

    class NotFoundError(AuthError):
        def __init__(self, message):
            super().__init__(message, 404)

    class DeletedError(AuthError):
        def __init__(self, message):
            super().__init__(message, 404)


class Account(BaseModel):
    """
    Contains all identifiable user information such as username, email, and more. All passwords must be hashed when
    being created in the database using the hash_password(str) method in the utils package.
    """
    username = fields.CharField(max_length=45)
    email = fields.CharField(unique=True, max_length=45)
    phone = fields.CharField(unique=True, max_length=20, null=True)
    password = fields.BinaryField()
    disabled = fields.BooleanField(default=False)
    verified = fields.BooleanField(default=False)

    class ErrorFactory(BaseErrorFactory):
        def get(self):
            error = None
            if not self.model:
                error = Account.NotFoundError('This account does not exist.')
            elif self.model.deleted:
                error = Account.DeletedError('This account has been permanently deleted.')
            elif self.model.disabled:
                error = Account.DisabledError()
            elif not self.model.verified:
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
        Retrieves account from an authentication session found within cookie.
        :param request: Sanic request parameter.
        :return: account
        """
        authentication_session = await AuthenticationSession().decode(request)
        return authentication_session.account

    class AccountError(AuthError):
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


class SessionFactory:
    """
    Prevents human error when creating sessions.
    """

    def __init__(self):
        self.session_cache_path = './resources/session-cache/'

    async def get_cached_session_code(self):
        """
        Retrieves a random cached code from a codes.txt file

        :return: code
        """
        async with aiofiles.open(self.session_cache_path + 'codes.txt', mode='r') as f:
            codes = await f.read()
            return random.choice(codes.split())

    async def cache_session_codes(self):
        """
        Generates up to 100 code and image variations in the resources/session-cache directory.
        """
        loop = asyncio.get_running_loop()
        image = ImageCaptcha(190, 90, fonts=[config['AUTH']['captcha_font']])
        if not path_exists(self.session_cache_path):
            async with aiofiles.open(self.session_cache_path + 'codes.txt', mode="w") as f:
                for i in range(100):
                    code = random_str(6)
                    await f.write(code + ' ')
                    await loop.run_in_executor(None, image.write, code, self.session_cache_path + code + '.png')

    async def get(self, session_type: str, request: Request, account: Account = None):
        """
        Creates and returns a session with all of the fulfilled requirements.

        :param session_type: The type of session being retrieved. Available types are: captcha, verification, and
        authentication.

        :param request: Sanic request parameter.

        :param account:

        :return:
        """
        await self.cache_session_codes()
        code = await self.get_cached_session_code()
        account = await Account.get_client(request) if account is None else account
        if session_type == 'captcha':
            return await CaptchaSession.create(ip=request_ip(request), code=code[:6])
        elif session_type == 'verification':
            return await VerificationSession.create(code=code, ip=request_ip(request), account=account)
        elif session_type == 'authentication':
            return await AuthenticationSession.create(account=account, ip=request_ip(request),
                                                      expiration_date=best_by(30))
        else:
            raise ValueError


class Session(BaseModel):
    """
    Used specifically for client side tracking. For example, an authentication session is stored on the client's browser
    in order to identify the client. All sessions should be created using the SessionFactory().
    """

    expiration_date = fields.DatetimeField(default=best_by, null=True)
    valid = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)
    attempts = fields.IntField(default=0)
    code = fields.CharField(max_length=6, null=True)

    def __init__(self, failed_attempt_error=None, **kwargs):
        super().__init__(**kwargs)
        self.cookie = self.__class__.__name__[:4].lower() + 'tkn'
        self.crosscheck_failed_error = failed_attempt_error

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'expiration_date': str(self.expiration_date),
            'valid': self.valid,
            'attempts': self.attempts
        }

    async def text_code(self, code_prefix="Your code is: "):
        """
        Sends account verification code via text.

        :param code_prefix: Message being sent with code, for example "Your code is: ".
        """
        await send_sms(self.account.phone, code_prefix + self.code)

    async def email_code(self, subject="Session Code", code_prefix='Your code is:\n\n '):
        """
        Sends account verification code via email.

        :param code_prefix: Message being sent with code, for example "Your code is: ".

        :param subject: Subject of email being sent with code.
        """
        await send_email(self.account.email, subject, code_prefix + self.code)

    async def crosscheck_code(self, code: str):
        """
        Used to check if code passed is equivalent to the session code.

        :param code: Code being cross-checked with session code.
        """
        if self.attempts > 5:
            raise self.MaximumAttemptsError
        elif self.code != code:
            self.attempts += 1
            await self.save(update_fields=['attempts'])
            raise self.crosscheck_failed_error
        else:
            self.valid = False
            await self.save(update_fields=['valid'])

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
        def get(self):
            error = None
            if self.model is None:
                error = Session.NotFoundError('Session could not be found.')
            elif not self.model.valid:
                error = Session.InvalidError()
            elif self.model.deleted:
                error = Session.DeletedError('Session has been deleted.')
            elif is_expired(self.model.expiration_date):
                error = Session.ExpiredError()
            return error

    class SessionError(AuthError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class MaximumAttemptsError(SessionError):
        def __init__(self):
            super().__init__('You\'ve reached the maximum amount of attempts.', 403)

    class DecodeError(SessionError):
        def __init__(self):
            super().__init__('Session is not available.', 403)

    class InvalidError(SessionError):
        def __init__(self):
            super().__init__('Session is invalid.', 401)

    class ExpiredError(SessionError):
        def __init__(self):
            super().__init__('Session has expired', 401)


class VerificationSession(Session):
    """
    Verifies an account via emailing or texting a code.
    """

    def __init__(self, **kwargs):
        super(VerificationSession, self).__init__(self.VerificationCodeError, **kwargs)

    class VerificationCodeError(Session.SessionError):
        def __init__(self):
            super().__init__('Your code does not match the verification code.', 400)


class CaptchaSession(Session):
    """
    Validates an client as human by forcing a user to correctly enter a captcha challenge.
    """

    def __init__(self, **kwargs):
        super(CaptchaSession, self).__init__(self.CaptchaChallengeError, **kwargs)

    class CaptchaChallengeError(Session.SessionError):
        def __init__(self):
            super().__init__('Your captcha does not match the captcha challenge.', 400)

    async def captcha_img(self, request):
        """
        Retrieves image path of captcha.

        :return: captcha_img_path
        """
        decoded_captcha = await CaptchaSession().decode(request)
        return './resources/session-cache/' + decoded_captcha.code + '.png'


class AuthenticationSession(Session):
    class UnknownLocationError(Session.SessionError):
        def __init__(self):
            super().__init__('Session in an unknown location.', 401)

    async def crosscheck_location(self, request):
        """
        Checks if client using session is in a known location (ip address). Prevents cookie jacking.

        :raises UnknownLocationError:
        """

        if not await AuthenticationSession.filter(ip=request_ip(request), account=self.account).exists():
            raise AuthenticationSession.UnknownLocationError()


class Role(BaseModel):
    """
    Assigned to an account to authorize an action. Used for role based authorization.
    """
    name = fields.CharField(max_length=45)

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'name': self.name,
        }

    class InsufficientRoleError(AuthError):
        def __init__(self):
            super().__init__('You do not have the required role for this action.', 403)


class Permission(BaseModel):
    """
    Assigned to an account to authorize an action. Used for wildcard based authorization.
    """
    wildcard = fields.CharField(max_length=45)

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'wildcard': self.wildcard,
        }

    class InsufficientPermissionError(AuthError):
        def __init__(self):
            super().__init__('You do not have the required permissions for this action.', 403)
