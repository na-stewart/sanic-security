import asyncio
import datetime
import os
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


from sanic_security.core.utils import get_ip, security_cache_path, dir_exists, config
from sanic_security.lib.smtp import send_email
from sanic_security.lib.twilio import send_sms


class BaseErrorFactory:
    """
    Easily raise or retrieve errors based off of model variable values. Validates the ability for a model to be utilized.
    """

    def get(self, model):
        """
        Retrieves an error based off of defined variable conditions.

        Args:
            model: Model being used to check for validation.

        Raises:
            SecurityError
        """
        raise NotImplementedError()

    def throw(self, model):
        """
        Raises an error that was retrieved in the get method.

        Args:
            model (BaseModel): Model being used to check for validation.

        Raises:
            SecurityError
        """
        error = self.get(model)
        if error:
            raise error


class SecurityError(ServerError):
    """
    Sanic Security related error.

    Args:
        message (str): Human readable error message.
        code (int): HTTP Error code.
    """

    def __init__(self, message, code):
        super().__init__(message, code)


class BaseModel(Model):
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        uid (bytes): Recommended identifier to be used for filtering or retrieval.
        account (Account): Parent account associated with this model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): This attribute allows you to mark a model as deleted and filter it from queries without fully
        removing it from the database.
    """

    id = fields.IntField(pk=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    account = fields.ForeignKeyField("models.Account", null=True)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    def json(self):
        """
        Retrieve a JSON serializable dict to be used in a HTTP request or response.

        Example:
            Below is an example of this method returning a dict to be used for JSON serialization.

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

        """
        raise NotImplementedError()

    class Meta:
        abstract = True

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


class Account(BaseModel):
    """
    Contains all identifiable user information.

    Attributes:
        username (str): Not used for any authentication or verification processes. May be displayed publicly.
        email (str): Used for authentication and verification processes (login and 2SV). Should not be displayed publicly.
        phone (str): Used for verification processes (2SV). Accounts do not have to have a mobile phone associated to them. Should not be displayed publicly.
        password (bytes): Must be created using the password_hash() method found in utils.py.
        disabled (bool): Renders an account unusable but available for moderators to investigate for infractions.
        verified (bool): Determines if an account has been through the two-step verification process before being allowed use.
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
                error = Account.NotFoundError("This account does not exist.")
            elif model.deleted:
                error = Account.DeletedError(
                    "This account has been permanently deleted."
                )
            elif model.disabled:
                error = Account.DisabledError()
            elif not model.verified:
                error = Account.UnverifiedError()
            return error

    def json(self):
        return {
            "uid": str(self.uid),
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "disabled": self.disabled,
            "verified": self.verified,
        }

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
            super().__init__(
                "Account with this email or phone number already exists.", 409
            )

    class TooManyCharsError(AccountError):
        def __init__(self):
            super().__init__("Email, username, or phone number is too long.", 400)

    class InvalidEmailError(AccountError):
        def __init__(self):
            super().__init__(
                "Please use a valid email format such as you@mail.com.", 400
            )

    class DisabledError(AccountError):
        def __init__(self):
            super().__init__("This account has been disabled.", 401)

    class PasswordMismatchError(AccountError):
        def __init__(self):
            super().__init__(
                "The password provided does not match account password.", 401
            )

    class UnverifiedError(AccountError):
        def __init__(self):
            super().__init__("Account requires verification.", 401)


class Session(BaseModel):
    """
    Used for client identification and validation. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Time the session expires and can no longer be used.
        valid (bool): Used to determine if a session can be utilized or not.
        ip (str): IP address of client creating session.
        cache_path (str): Session cache path.
    """

    expiration_date = fields.DatetimeField(null=True)
    valid = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)
    cache_path = "./resources/security-cache/session/"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cookie = config["AUTH"]["name"].strip() + "_" + self.__class__.__name__

    def json(self):
        return {
            "uid": str(self.uid),
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "account": self.account.email
            if isinstance(self.account, Account)
            else None,
            "valid": self.valid,
        }

    def encode(self, response: HTTPResponse, secure=True, same_site: str = "lax"):
        """
        Transforms session into jwt and then is stored in a cookie.

        Args:
            secure (bool): If true, connections must be SSL encrypted (aka https).
            response (HTTPResponse): Sanic response object used to store JWT into a cookie on the client.
            same_site (bool): : Allows you to declare if your cookie should be restricted to a first-party or same-site context.
        """
        payload = {
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
            "uid": str(self.uid),
            "ip": self.ip,
        }
        encoded = jwt.encode(payload, config["AUTH"]["secret"], "HS256")
        response.cookies[self.cookie] = encoded
        response.cookies[self.cookie]["secure"] = secure
        response.cookies[self.cookie]["samesite"] = same_site

    def decode_raw(self, request: Request):
        """
        Decodes JWT token from client cookie into a python dict.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session_dict

        """
        cookie = request.cookies.get(self.cookie)
        try:
            if not cookie:
                raise DecodeError("Token can not be null.")
            else:
                return jwt.decode(cookie, config["AUTH"]["secret"], "HS256")
        except DecodeError as e:
            raise Session.DecodeError(e)

    async def decode(self, request: Request):
        """
        Decodes JWT token from client cookie to a Sanic Security session.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session

        Raises:
            DecodeError
        """
        decoded = self.decode_raw(request)
        return (
            await self.filter(uid=decoded.get("uid"))
            .prefetch_related("account")
            .first()
        )

    class Meta:
        abstract = True

    class ErrorFactory(BaseErrorFactory):
        def get(self, model):
            error = None
            if model is None:
                error = Session.NotFoundError("Session could not be found.")
            elif not model.valid:
                error = Session.InvalidError()
            elif model.deleted:
                error = Session.DeletedError("Session has been deleted.")
            elif datetime.datetime.now(datetime.timezone.utc) >= model.expiration_date:
                error = Session.ExpiredError()
            return error

    class SessionError(SecurityError):
        """
        A session related error.

        Args:
            message (str): Human readable error message.
            code (int): HTTP Error code.
        """

        def __init__(self, message, code):
            super().__init__(message, code)

    class DecodeError(SessionError):
        def __init__(self, exception):
            super().__init__(
                "Session cookie could not be decoded. " + str(exception), 400
            )

    class InvalidError(SessionError):
        def __init__(self):
            super().__init__("Session is invalid.", 401)

    class ExpiredError(SessionError):
        def __init__(self):
            super().__init__("Session has expired", 401)


class VerificationSession(Session):
    """
    Used for a client verification method that requires some form of code, challenge, or key.

    Attributes:
        attempts (int): The amount of incorrect times a user entered a code not equal to this verification sessions code.
        code (str): Used as a secret key that would be sent or provided in a way that makes it difficult for malicious actors to obtain.
    """

    attempts = fields.IntField(default=0)
    code = fields.CharField(max_length=10, null=True)

    @staticmethod
    def initialize_cache(app: Sanic):
        """
        Creates session cache directory and generates required files.

        Args:
            app (Sanic): Sanic Framework app.
        """
        raise NotImplementedError()

    @staticmethod
    async def get_random_cached_code():
        """
        Retrieves a random cached verification session code.
        """
        raise NotImplementedError()

    async def crosscheck(self, code: str):
        """
        Used to check if code passed is equivalent to the verification session code.

        Args:
            code (str): Code being cross-checked with verification session code.

        Raises:
            CrossCheckError
        """
        if self.attempts >= 5:
            raise self.MaximumAttemptsError
        elif self.code != code:
            self.attempts += 1
            await self.save(update_fields=["attempts"])
            raise self.CrosscheckError()
        else:
            self.valid = False
            await self.save(update_fields=["valid"])

    class Meta:
        abstract = True

    class CrosscheckError(Session.SessionError):
        def __init__(self):
            super().__init__("Session crosschecking attempt was incorrect", 401)

    class MaximumAttemptsError(Session.SessionError):
        def __init__(self):
            super().__init__(
                "You've reached the maximum amount of attempts for this session.", 401
            )


class TwoStepSession(VerificationSession):
    """
    An account is granted access to a website or application only after successfully presenting two or more pieces of
    evidence. Knowledge (something only the user knows) and possession (something only the user has). For example, in
    order to successfully perform an action requiring TwoStepVerification, a client must supply the correct code associated
    with this session that can be found in an email or a text.
    """

    @staticmethod
    async def get_random_cached_code():
        async with aiofiles.open(
            f"{security_cache_path}/verification/codes.txt", mode="r"
        ) as f:
            codes = await f.read()
            return random.choice(codes.split())

    @staticmethod
    def initialize_cache(app: Sanic):
        @app.listener("before_server_start")
        async def generate_codes(app, loop):
            if not dir_exists(f"{security_cache_path}/verification"):
                async with aiofiles.open(
                    f"{security_cache_path}/verification/codes.txt", mode="w"
                ) as f:
                    for i in range(100):
                        code = "".join(
                            random.choices(string.ascii_letters + string.digits, k=10)
                        )
                        await f.write(code + " ")

    async def text_code(self, code_prefix="Your code is: "):
        """
        Sends account associated with this session the code via text.

        Args:
            code_prefix (str): Message being sent with code, for example "Your code is: ".
        """
        await send_sms(self.account.phone, code_prefix + self.code)

    async def email_code(
        self, subject="Session Code", code_prefix="Your code is:\n\n "
    ):
        """
        Sends account associated with this session the code via email.

        Args:
            code_prefix (str): Message being sent with code, for example "Your code is: ".
            subject (str): Subject of email being sent with code.
        """
        await send_email(self.account.email, subject, code_prefix + self.code)


class CaptchaSession(VerificationSession):
    """
    Validates an client as human by forcing a user to correctly enter a captcha challenge.
    """

    @staticmethod
    def initialize_cache(app: Sanic):
        @app.listener("before_server_start")
        async def generate_codes(app, loop):
            if not dir_exists(f"{security_cache_path}/captcha"):
                loop = asyncio.get_running_loop()
                image = ImageCaptcha(190, 90, fonts=[config["AUTH"]["captcha_font"]])
                for i in range(100):
                    code = "".join(
                        random.choices(
                            "123456789qQeErRtTyYuUiIpPaAdDfFgGhHkKlLbBnN", k=6
                        )
                    )
                    await loop.run_in_executor(
                        None,
                        image.write,
                        code,
                        f"{security_cache_path}/captcha/{code}.png",
                    )

    @staticmethod
    def get_random_cached_code():
        return random.choice(os.listdir(f"{security_cache_path}/captcha")).split(".")[0]

    def get_image(self):
        """
        Retrieves cached captcha image challange path.

        Returns:
            captcha_image_path
        """
        return f"{security_cache_path}/captcha/{self.code}.png"


class AuthenticationSession(Session):
    """
    Used to authenticate a client and provide access to a user's account.
    """

    class UnknownLocationError(Session.SessionError):
        def __init__(self):
            super().__init__("Session in an unknown location.", 401)

    async def crosscheck_location(self, request):
        """
        Checks if client using session is in a known location (ip address). Prevents cookie jacking.

        Raises:
            UnknownLocationError:
        """

        if not await AuthenticationSession.filter(
            ip=get_ip(request), account=self.account
        ).exists():
            raise AuthenticationSession.UnknownLocationError()


class SessionFactory:
    """
    Prevents human error when creating sessions.
    """

    def generate_expiration_date(self, days: int = 0, minutes: int = 0):
        """
        Creates an expiration date. Adds days to current datetime.

        Args:
            days (int):  Days to be added to current time.
            minutes (int): Minutes to be added to the current time.

        Returns:
            expiration_date
        """
        return datetime.datetime.utcnow() + datetime.timedelta(
            days=days, minutes=minutes
        )

    async def get(self, session_type: str, request: Request, account: Account = None):
        """
         Creates and returns a session with all of the fulfilled requirements.

        Args:
            session_type (str): The type of session being retrieved. Available types are: captcha, twostep, and authentication.
            request (Request):  Sanic request paramater.
            account (Account): Account being associated to a session.

        Returns:
            session

        Raises:
            ValueError
        """
        if session_type == "captcha":
            return await CaptchaSession.create(
                ip=get_ip(request),
                code=CaptchaSession.get_random_cached_code(),
                expiration_date=self.generate_expiration_date(minutes=1),
            )
        elif session_type == "twostep":
            return await TwoStepSession.create(
                code=await TwoStepSession.get_random_cached_code(),
                ip=get_ip(request),
                account=account,
                expiration_date=self.generate_expiration_date(minutes=5),
            )
        elif session_type == "authentication":
            return await AuthenticationSession.create(
                account=account,
                ip=get_ip(request),
                expiration_date=self.generate_expiration_date(days=30),
            )
        else:
            raise ValueError("Invalid session type.")


class Role(BaseModel):
    """
    Assigned to an account to authorize an action. Used for role based authorization.

    Attributes:
        name (str): Name of the role.
    """

    name = fields.CharField(max_length=45)

    def json(self):
        return {
            "uid": str(self.uid),
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
        }

    class InsufficientRoleError(SecurityError):
        def __init__(self):
            super().__init__("Insufficient roles required for this action.", 403)


class Permission(BaseModel):
    """
    Assigned to an account to authorize an action. Used for wildcard based authorization.

    Attributes:
        wildcard (str): The wildcard for this permission.
    """

    wildcard = fields.CharField(max_length=45)

    def json(self):
        return {
            "uid": str(self.uid),
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "wildcard": self.wildcard,
        }

    class InsufficientPermissionError(SecurityError):
        def __init__(self):
            super().__init__("Insufficient permissions required for this action.", 403)
