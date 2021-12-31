import datetime
import os
import random
import string
import uuid

import jwt
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, file
from tortoise import fields, Model
from tortoise.exceptions import DoesNotExist

from sanic_security.configuration import config as security_config
from sanic_security.exceptions import *
from sanic_security.utils import get_ip, dir_exists


class BaseModel(Model):
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): Renders this account filterable without removing from the database.
    """

    id = fields.IntField(pk=True)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    def validate(self):
        """
        Raises an error with respect to variable values.

        Raises:
            SecurityError
        """
        raise NotImplementedError()

    def json(self) -> dict:
        """
        A JSON serializable dict to be used in a HTTP request or response.

        Example:
            Below is an example of this method returning a dict to be used for JSON serialization.

                def json(self):
                    return {
                        'id': id,
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


class Account(BaseModel):
    """
    Contains all identifiable user information.

    Attributes:
        username (str): Public identifier.
        email (str): Private identifier and can be used for verification.
        phone (str): Mobile phone number with country code included and can be used for verification. May be null or empty.
        password (str): Password of account for protection. Must be hashed via Argon.
        disabled (bool): Renders the account unusable but available.
        verified (bool): Renders the account unusable until verified via two-step verification or other method.
        roles (list): Roles associated with this account.
    """

    username = fields.CharField(max_length=32)
    email = fields.CharField(unique=True, max_length=255)
    phone = fields.CharField(unique=True, max_length=14, null=True)
    password = fields.CharField(max_length=255)
    disabled = fields.BooleanField(default=False)
    verified = fields.BooleanField(default=False)
    roles = fields.ManyToManyField(
        "models.Role", related_name="roles", through="account_role"
    )

    def json(self):
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "disabled": self.disabled,
            "verified": self.verified,
        }

    def validate(self):
        if self.deleted:
            raise DeletedError("Account has been deleted.")
        elif not self.verified:
            raise UnverifiedError()
        elif self.disabled:
            raise DisabledError()

    @staticmethod
    async def get_via_email(email: str):
        """
        Retrieve an account with an email.

        Args:
            email (str): Email associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            account = await Account.filter(email=email).get()
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this email does not exist.")

    @staticmethod
    async def get_via_username(username: str):
        """
        Retrieve an account with a username.

        Args:
            username (str): Username associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            account = await Account.filter(username=username).get()
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this username does not exist.")

    @staticmethod
    async def get_via_phone(phone: str):
        """
        Retrieve an account with a phone number.

        Args:
            phone (str): Phone number associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            account = await Account.filter(phone=phone).get()
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this phone number does not exist.")


class Session(BaseModel):
    """
    Used for client identification and validation. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client creating session.
        token (uuid): Token stored on the client's browser in a cookie for identification.
        refresh_token (uuid): Token stored on the client's browser in a cookie for refreshing session.
        bearer (Account): Account associated with this session.
    """

    expiration_date = fields.DatetimeField(null=True)
    active = fields.BooleanField(default=True)
    ip = fields.CharField(max_length=16)
    token = fields.UUIDField(unique=True, default=uuid.uuid4, max_length=36)
    refresh_token = fields.UUIDField(unique=True, default=uuid.uuid4, max_length=36)
    bearer = fields.ForeignKeyField("models.Account", null=True)

    def json(self):
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": self.bearer.email if isinstance(self.bearer, Account) else None,
            "active": self.active,
        }

    def validate(self):
        if self.deleted:
            raise DeletedError("Session has been deleted.")
        elif (
            self.expiration_date
            and datetime.datetime.now(datetime.timezone.utc) >= self.expiration_date
        ):
            raise ExpiredError()
        elif not self.active:
            raise DeactivatedError()

    async def crosscheck_location(self, request):
        """
        Checks if client using session is in a known location (ip address).

        Raises:
            SessionError
        """
        ip = get_ip(request)
        if not await self.filter(ip=ip, bearer=self.bearer).exists():
            logger.warning(
                f"Client ({self.bearer.email}/{ip}) ip address is unrecognised"
            )
            raise SessionError("Unrecognised location.", 401)

    def encode(self, response: HTTPResponse):
        """
        Transforms session into jwt and then is stored in a cookie.

        Args:
            response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
        """
        payload = {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "token": str(self.token),
            "refresh_token": str(self.token),
            "ip": self.ip,
        }
        cookie = f"{security_config.SESSION_PREFIX}_{self.__class__.__name__.lower()[:4]}_session"
        response.cookies[cookie] = jwt.encode(
            payload, security_config.SECRET, security_config.SESSION_ENCODING_ALGORITHM
        )
        response.cookies[cookie]["httponly"] = security_config.SESSION_HTTPONLY
        response.cookies[cookie]["samesite"] = security_config.SESSION_SAMESITE
        response.cookies[cookie]["secure"] = security_config.SESSION_SECURE
        if security_config.SESSION_EXPIRES_ON_CLIENT and self.expiration_date:
            response.cookies[cookie]["expires"] = self.expiration_date
        if security_config.SESSION_DOMAIN:
            response.cookies[cookie]["domain"] = security_config.SESSION_DOMAIN

    @classmethod
    def decode_raw(cls, request: Request) -> dict:
        """
        Decodes JWT token from client cookie into a python dict.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session_dict

        Raises:
            SessionError
        """
        cookie = request.cookies.get(
            f"{security_config.SESSION_PREFIX}_{cls.__name__.lower()[:4]}_session"
        )
        try:
            if not cookie:
                raise SessionError(f"No session provided by client.", 400)
            else:
                return jwt.decode(
                    cookie,
                    security_config.SECRET,
                    security_config.SESSION_ENCODING_ALGORITHM,
                )
        except DecodeError as e:
            raise SessionError(str(e), 400)

    @classmethod
    async def decode(cls, request: Request):
        """
        Decodes session JWT from client cookie to a Sanic Security session.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session

        Raises:
            NotFoundError
            SessionError
        """
        try:
            decoded_raw = cls.decode_raw(request)
            decoded_session = (
                await cls.filter(token=decoded_raw["token"])
                .prefetch_related("bearer")
                .get()
            )
        except DoesNotExist:
            raise NotFoundError("Session could not be found.")
        return decoded_session

    class Meta:
        abstract = True

    @classmethod
    async def redeem(cls, request: Request):
        """
        Redeems client refresh token and deactivates the session associated to the decoded session JWT so the refresh token cannot be used again.

        Args:
            request (Request): Sanic request parameter.
        """
        decoded_raw = cls.decode_raw(request)
        decoded_session = await cls.filter(
            refresh_token=decoded_raw["refresh_token"]
        ).get()
        if decoded_session.active and not decoded_session.deleted:
            decoded_session.active = False
            await decoded_session.save(update_fields=["active"])
            return decoded_session
        else:
            logger.warning(
                f"Client ({decoded_session.bearer.email}/{get_ip(request)}) is using an invalid refresh token."
            )
            raise DeactivatedError("Invalid refresh token.")


class VerificationSession(Session):
    """
    Used for a client verification method that requires some form of code, challenge, or key.

    Attributes:
        attempts (int): The amount of incorrect times a user entered a code not equal to this verification sessions code.
        code (str): Used as a secret key that would be sent via email, text, etc to complete the verification challenge.
        cache (str): Session cache path.
    """

    attempts = fields.IntField(default=0)
    code = fields.CharField(max_length=10, null=True)
    cache = security_config.CACHE

    @classmethod
    def _initialize_cache(cls):
        """
        Creates verification session cache and generates required files.
        """
        raise NotImplementedError()

    @classmethod
    def get_random_code(cls) -> str:
        """
        Retrieves a random cached verification session code.
        """
        raise NotImplementedError()

    async def crosscheck_code(self, request: Request, code: str):
        """
        Used to check if code passed is equivalent to the session code.

        Args:
            code (str): Code being cross-checked with session code.
            request (Request): Sanic request parameter.

        Raises:
            SessionError
            InvalidError
        """
        await self.crosscheck_location(request)
        if self.code != code:
            if self.attempts < 5:
                self.attempts += 1
                await self.save(update_fields=["attempts"])
                raise SessionError("The value provided does not match.", 401)
            else:
                logger.warning(
                    f"Client ({self.bearer.email}/{get_ip(request)}) has maxed out on session challenge attempts"
                )
                self.valid = False
                await self.save(update_fields=["valid"])
                raise DeactivatedError()
        else:
            self.valid = False
            await self.save(update_fields=["valid"])

    class Meta:
        abstract = True


class TwoStepSession(VerificationSession):
    """
    Validates a client using a code sent via email or text.
    """

    @classmethod
    def _initialize_cache(cls):
        if not dir_exists(f"{cls.cache}/verification"):
            with open(f"{cls.cache}/verification/codes.txt", "w") as f:
                for i in range(100):
                    code = "".join(
                        random.choices(string.ascii_letters + string.digits, k=10)
                    )
                    f.write(f"{code} ")
            logger.info("Two-step session cache initialised")

    @classmethod
    def get_random_code(cls):
        cls._initialize_cache()
        with open(f"{cls.cache}/verification/codes.txt", "r") as f:
            return random.choice(f.read().split())

    class Meta:
        table = "two_step_session"


class CaptchaSession(VerificationSession):
    """
    Validates a client as human with a captcha challenge.
    """

    @classmethod
    def _initialize_cache(cls):
        if not dir_exists(f"{cls.cache}/captcha"):
            image = ImageCaptcha(190, 90, fonts=[security_config.CAPTCHA_FONT])
            for i in range(100):
                code = "".join(
                    random.choices("123456789qQeErRtTyYiIaAdDfFgGhHlLbBnN", k=6)
                )
                image.write(code, f"{cls.cache}/captcha/{code}.png")
            logger.info("Captcha session cache initialised")

    @classmethod
    def get_random_code(cls):
        cls._initialize_cache()
        return random.choice(os.listdir(f"{cls.cache}/captcha")).split(".")[0]

    async def get_image(self) -> HTTPResponse:
        """
        Retrieves captcha image file.

        Returns:
            captcha_image
        """
        return await file(f"{self.cache}/captcha/{self.code}.png")

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    """
    Used to authenticate a client and provide access to a user's account.

    Attributes:
        two_factor (bool): Determines if authentication session requires a second factor to be used for authentication.
    """

    two_factor = fields.BooleanField(default=False)

    class Meta:
        table = "authentication_session"


class SessionFactory:
    """
    Used to create and retrieve a session with pre-determined values.
    """

    async def get(
        self, session_type: str, request: Request, account: Account = None, **kwargs
    ):
        """
        Creates and returns a session with all of the fulfilled requirements.

        Args:
            session_type (str): The type of session being retrieved. Available types are: captcha, two-step, and authentication.
            request (Request): Sanic request parameter.
            account (Account): Account being associated to the session.
            use_refresh_token (bool) Create new session if client session refresh token is valid.
            kwargs: Extra arguments applied during session creation.

        Returns:
            session

        Raises:
            ValueError
        """
        if session_type == "captcha":
            return await CaptchaSession.create(
                **kwargs,
                ip=get_ip(request),
                code=CaptchaSession.get_random_code(),
                bearer=account,
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(seconds=security_config.CAPTCHA_SESSION_EXPIRATION)
                if security_config.CAPTCHA_SESSION_EXPIRATION != 0
                else None,
            )
        elif session_type == "two-step":
            return await TwoStepSession.create(
                **kwargs,
                code=TwoStepSession.get_random_code(),
                ip=get_ip(request),
                bearer=account,
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(
                    seconds=security_config.TWO_STEP_SESSION_EXPIRATION
                )
                if security_config.TWO_STEP_SESSION_EXPIRATION != 0
                else None,
            )
        elif session_type == "authentication":
            return await AuthenticationSession.create(
                **kwargs,
                bearer=account,
                ip=get_ip(request),
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(
                    seconds=security_config.AUTHENTICATION_SESSION_EXPIRATION
                )
                if security_config.AUTHENTICATION_SESSION_EXPIRATION != 0
                else None,
            )
        else:
            raise ValueError("Invalid session type.")


class Role(BaseModel):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be seperated via comma and in wildcard format (printer:query, printer:query,delete).
    """

    name = fields.CharField(max_length=255)
    description = fields.CharField(max_length=255)
    permissions = fields.CharField(max_length=255, null=True)

    def json(self):
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions,
        }
