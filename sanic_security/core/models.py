import asyncio
import datetime
import random
import string
import uuid
import aiofiles
import jwt
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.request import Request
from sanic.response import HTTPResponse
from tortoise import fields, Model
from sanic_security.core.config import config
from sanic_security.core.utils import path_exists, get_ip
from sanic_security.lib.smtp import send_email
from sanic_security.lib.twilio import send_sms


class BaseErrorFactory:
    """
    Easily raise or retrieve errors based off of variable values. Validates the ability for a model to be utilized.
    """

    def get(self, model):
        """
        Retrieves an error if certain conditions are met.
        :return: error
        """
        raise NotImplementedError()

    def throw(self, model):
        """
        Retrieves an error and raises it if certain conditions are met.
        :return: error
        """
        error = self.get(model)
        if error:
            raise error


class SecurityError(ServerError):
    """
    Base error for all Sanic Security related errors.
    """

    def __init__(self, message, code=None):
        super().__init__(message, code)


class BaseModel(Model):
    """
    Base Sanic Security model that all other models derive from.
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

    class NotFoundError(SecurityError):
        def __init__(self, message):
            super().__init__(message, 404)

    class DeletedError(SecurityError):
        def __init__(self, message):
            super().__init__(message, 404)


class Account(BaseModel):
    """
    Contains all identifiable user information such as username, email, and more. All passwords must be hashed when
    being created in the database using the hash_pw(str) method.
    """
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

    class AccountError(SecurityError):
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
            super().__init__("This account has been disabled.", 401)

    class IncorrectPasswordError(AccountError):
        def __init__(self):
            super().__init__('The password provided is incorrect.', 401)

    class UnverifiedError(AccountError):
        def __init__(self):
            super().__init__('Account requires verification.', 401)


class Session(BaseModel):
    """
    Used specifically for client side tracking. For example, an authentication session is stored on the client's browser
    in order to identify the client. All sessions should be created using the SessionFactory().
    """

    expiration_date = fields.DatetimeField(null=True)
    valid = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)
    attempts = fields.IntField(default=0)
    code = fields.CharField(max_length=8, null=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cookie = config['AUTH']['name'].strip() + '_' + self.__class__.__name__

    def json(self):
        return {
            'uid': str(self.uid),
            'date_created': str(self.date_created),
            'date_updated': str(self.date_updated),
            'expiration_date': str(self.expiration_date),
            'account': self.account.email if isinstance(self.account, Account) else None,
            'valid': self.valid,
            'attempts': self.attempts
        }

    @staticmethod
    def initialize_cache(app: Sanic):
        """
        Caches up to 100 code and image variations.
        """

        @app.listener("before_server_start")
        async def generate_codes(app, loop):
            session_cache = './resources/security-cache/session/'
            loop = asyncio.get_running_loop()
            image = ImageCaptcha(190, 90, fonts=[config['AUTH']['captcha_font']])
            if not path_exists(session_cache):
                async with aiofiles.open(session_cache + 'codes.txt', mode="w") as f:
                    for i in range(100):
                        code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                        await f.write(code + ' ')
                        await loop.run_in_executor(None, image.write, code[:6], session_cache + code[:6] + '.png')

    @staticmethod
    async def get_code():
        """
        Retrieves a random cached code from a codes.txt file

        :return: code
        """
        async with aiofiles.open('./resources/security-cache/session/codes.txt', mode='r') as f:
            codes = await f.read()
            return random.choice(codes.split())

    async def crosscheck_code(self, code: str):
        """
        Used to check if code passed is equivalent to the session code.

        :param code: Code being cross-checked with session code.
        """
        if self.attempts >= 5:
            raise self.MaximumAttemptsError
        elif self.code != code:
            self.attempts += 1
            await self.save(update_fields=['attempts'])
            raise self.CrosscheckError()
        else:
            self.valid = False
            await self.save(update_fields=['valid'])

    def encode(self, response: HTTPResponse, secure=True, same_site: str = 'lax'):
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
        encoded = jwt.encode(payload, config['AUTH']['secret'], 'HS256')
        response.cookies[self.cookie] = encoded
        response.cookies[self.cookie]['secure'] = secure
        response.cookies[self.cookie]['samesite'] = same_site

    def decode_raw(self, request: Request):
        """
        Decodes JWT token in cookie to dict.

        :param request: Sanic request parameter.

        :return: raw
        """
        cookie = request.cookies.get(self.cookie)
        try:
            if not cookie:
                raise DecodeError('Token can not be null.')
            else:
                return jwt.decode(cookie, config['AUTH']['secret'], 'HS256')
        except DecodeError as e:
            raise Session.DecodeError(e)

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
            elif datetime.datetime.now(datetime.timezone.utc) >= model.expiration_date:
                error = Session.ExpiredError()
            return error

    class SessionError(SecurityError):
        def __init__(self, message, code):
            super().__init__(message, code)

    class MaximumAttemptsError(SessionError):
        def __init__(self):
            super().__init__('You\'ve reached the maximum amount of attempts for this session.', 401)

    class DecodeError(SessionError):
        def __init__(self, exception):
            super().__init__('Session cookie could not be decoded. ' + str(exception), 400)

    class InvalidError(SessionError):
        def __init__(self):
            super().__init__('Session is invalid.', 401)

    class CrosscheckError(SessionError):
        def __init__(self):
            super().__init__('Session crosschecking attempt was incorrect', 401)

    class ExpiredError(SessionError):
        def __init__(self):
            super().__init__('Session has expired', 401)


class SessionFactory:
    """
    Prevents human error when creating sessions.
    """

    def generate_expiration_date(self, days: int = 0, minutes: int = 0):
        """
        Creates an expiration date. Adds days to current datetime.

        :param days: days to be added to current time.

        :param minutes: minutes to be added to the current time.

        :return: expiration_date
        """
        return datetime.datetime.utcnow() + datetime.timedelta(days=days, minutes=minutes)

    async def _account_via_decoded(self, request: Request, session: Session):
        """
        Extracts account from decoded session. This method was created purely to prevent repetitive code.

        :param request: Sanic request parameter.

        :param session: Session being decoded to retrieve account from

        :return: account
        """
        decoded_session = await session.decode(request)
        return decoded_session.account

    async def get(self, session_type: str, request: Request, account: Account = None):
        """
        Creates and returns a session with all of the fulfilled requirements.

        :param session_type: The type of session being retrieved. Available types are: captcha, verification, and
        authentication.

        :param request: Sanic request parameter.

        :param account: Account being associated to to a session.

        :return: session
        """
        code = await Session.get_code()
        if session_type == 'captcha':
            return await CaptchaSession.create(ip=get_ip(request), code=code[:6],
                                               expiration_date=self.generate_expiration_date(minutes=1))
        elif session_type == 'verification':
            return await VerificationSession.create(code=code, ip=get_ip(request), account=account,
                                                    expiration_date=self.generate_expiration_date(minutes=5))
        elif session_type == 'authentication':
            return await AuthenticationSession.create(account=account, ip=get_ip(request),
                                                      expiration_date=self.generate_expiration_date(days=30))
        else:
            raise ValueError('Invalid session type.')


class VerificationSession(Session):
    """
    Used to verify an account's email or mobile. Can be used in order to validate the person utilizing
    an account is the actual owner.
    """

    async def text_code(self, code_prefix="Your code is: "):
        """
        Sends verification code via text.

        :param code_prefix: Message being sent with code, for example "Your code is: ".
        """
        await send_sms(self.account.phone, code_prefix + self.code)

    async def email_code(self, subject="Session Code", code_prefix='Your code is:\n\n '):
        """
        Sends verification code via email.

        :param code_prefix: Message being sent with code, for example "Your code is: ".

        :param subject: Subject of email being sent with code.
        """
        await send_email(self.account.email, subject, code_prefix + self.code)


class CaptchaSession(Session):
    """
    Validates a client as human by correctly entering a captcha challenge.
    """

    @staticmethod
    async def captcha_img(request):
        """
        Retrieves image path of captcha.

        :return: captcha_img_path
        """
        decoded_captcha = await CaptchaSession().decode(request)
        return './resources/security-cache/session/' + decoded_captcha.code + '.png'


class AuthenticationSession(Session):
    class UnknownLocationError(Session.SessionError):
        def __init__(self):
            super().__init__('Session in an unknown location.', 401)

    async def crosscheck_location(self, request):
        """
        Checks if client using session is in a known location (ip address). Prevents cookie jacking.

        :raises UnknownLocationError:
        """

        if not await AuthenticationSession.filter(ip=get_ip(request), account=self.account).exists():
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

    class InsufficientRoleError(SecurityError):
        def __init__(self):
            super().__init__('Insufficient roles required for this action.', 403)


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

    class InsufficientPermissionError(SecurityError):
        def __init__(self):
            super().__init__('Insufficient permissions required for this action.', 403)
