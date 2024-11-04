import base64
import datetime
from io import BytesIO
from typing import Union

import jwt
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, raw
from tortoise import fields, Model
from tortoise.exceptions import DoesNotExist

from sanic_security.configuration import config as security_config
from sanic_security.exceptions import *
from sanic_security.utils import get_ip, get_code, get_expiration_date

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


class BaseModel(Model):
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): Renders the model filterable without removing from the database.
    """

    id: int = fields.IntField(pk=True)
    date_created: datetime.datetime = fields.DatetimeField(auto_now_add=True)
    date_updated: datetime.datetime = fields.DatetimeField(auto_now=True)
    deleted: bool = fields.BooleanField(default=False)

    def validate(self) -> None:
        """
        Raises an error with respect to state.

        Raises:
            SecurityError
        """
        raise NotImplementedError()

    @property
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
        phone (str): Mobile phone number with country code included and can be used for verification. Can be null or empty.
        password (str): Password of account for protection. Must be hashed via Argon2.
        disabled (bool): Renders the account unusable but available.
        verified (bool): Renders the account unusable until verified via two-step verification or other method.
        roles (ManyToManyRelation[Role]): Roles associated with this account.
    """

    username: str = fields.CharField(unique=True, max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role"
    )

    def validate(self) -> None:
        """
        Raises an error with respect to account state.

        Raises:
            DeletedError
            UnverifiedError
            DisabledError
        """
        if self.deleted:
            raise DeletedError("Account has been deleted.")
        elif not self.verified:
            raise UnverifiedError()
        elif self.disabled:
            raise DisabledError()

    async def disable(self):
        """
        Renders account unusable.

        Raises:
            DisabledError
        """
        if self.disabled:
            raise DisabledError("Account is already disabled.")
        else:
            self.disabled = True
            await self.save(update_fields=["disabled"])
            logger.info(f"Account {self.id} has been disabled.")

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "disabled": self.disabled,
            "verified": self.verified,
        }

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
            account = await Account.filter(email=email, deleted=False).get()
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
            account = await Account.filter(username=username, deleted=False).get()
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this username does not exist.")

    @staticmethod
    async def get_via_credential(credential: str):
        """
        Retrieve an account with an email or username.

        Args:
            credential (str): Email or username associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            account = await Account.get_via_email(credential)
        except NotFoundError as e:
            if security_config.ALLOW_LOGIN_WITH_USERNAME:
                account = await Account.get_via_username(credential)
            else:
                raise e
        return account

    @staticmethod
    async def get_via_header(request: Request):
        """
        Retrieve the account the client is logging into and client's password attempt via the basic authorization header.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            account, password

        Raises:
            NotFoundError
        """
        if request.headers.get("Authorization"):
            authorization_type, credentials = request.headers.get(
                "Authorization"
            ).split()
            if authorization_type == "Basic":
                email_or_username, password = (
                    base64.b64decode(credentials).decode().split(":")
                )
                account = await Account.get_via_credential(email_or_username)
                return account, password
            else:
                raise CredentialsError("Invalid authorization type.")
        else:
            raise CredentialsError("Authorization header not provided.")

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
            account = await Account.filter(phone=phone, deleted=False).get()
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this phone number does not exist.")


class Session(BaseModel):
    """
    Used for client identification and verification. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Date and time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client creating session.
        bearer (ForeignKeyRelation[Account]): Account associated with this session.
    """

    expiration_date: datetime.datetime = fields.DatetimeField(null=True)
    active: bool = fields.BooleanField(default=True)
    ip: str = fields.CharField(max_length=16)
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", null=True
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def validate(self) -> None:
        """
        Raises an error with respect to session state.

        Raises:
            DeletedError
            ExpiredError
            DeactivatedError
        """
        if self.deleted:
            raise DeletedError("Session has been deleted.")
        elif not self.active:
            raise DeactivatedError()
        elif (
            self.expiration_date
            and datetime.datetime.now(datetime.timezone.utc) >= self.expiration_date
        ):
            raise ExpiredError()

    async def deactivate(self):
        """
        Renders session deactivated and unusable.

        Raises:
            DeactivatedError
        """
        if self.active:
            self.active = False
            await self.save(update_fields=["active"])
            logger.info(f"Session {self.id} has been deactivated.")
        else:
            raise DeactivatedError("Session is already deactivated.", 403)

    def encode(self, response: HTTPResponse) -> None:
        """
        Transforms session into JWT and then is stored in a cookie.

        Args:
            response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
        """
        cookie = (
            f"{security_config.SESSION_PREFIX}_{self.__class__.__name__.lower()[:7]}"
        )
        encoded_session = jwt.encode(
            {
                "id": self.id,
                "date_created": str(self.date_created),
                "expiration_date": str(self.expiration_date),
                "ip": self.ip,
            },
            security_config.SECRET,
            security_config.SESSION_ENCODING_ALGORITHM,
        )
        response.cookies.add_cookie(
            cookie,
            str(encoded_session),
            httponly=security_config.SESSION_HTTPONLY,
            samesite=security_config.SESSION_SAMESITE,
            secure=security_config.SESSION_SECURE,
        )
        if self.expiration_date:  # Overrides refresh expiration.
            response.cookies.get_cookie(cookie).expires = (
                self.refresh_expiration_date
                if (
                    hasattr(self, "refresh_expiration_date")
                    and self.refresh_expiration_date
                )
                else self.expiration_date
            )

        if security_config.SESSION_DOMAIN:
            response.cookies.get_cookie(cookie).domain = security_config.SESSION_DOMAIN

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": (
                self.bearer.username if isinstance(self.bearer, Account) else None
            ),
            "active": self.active,
        }

    @property
    def anonymous(self) -> bool:
        """
        Determines if an account is associated with session.

        Returns:
            anonymous
        """
        return self.bearer is None

    @classmethod
    async def new(
        cls,
        request: Request,
        account: Account,
        **kwargs: Union[int, str, bool, float, list, dict],
    ):
        """
        Creates session with pre-set values.

        Args:
            request (Request): Sanic request parameter.
            account (Account): Account being associated to the session.
            **kwargs (dict[str, Union[int, str, bool, float, list, dict]]): Extra arguments applied during session creation.

        Returns:
            session
        """
        raise NotImplementedError()

    @classmethod
    async def get_associated(cls, account: Account):
        """
        Retrieves sessions associated to an account.

        Args:
            account (Request): Account associated with sessions being retrieved.

        Returns:
            sessions

        Raises:
            NotFoundError
        """
        sessions = await cls.filter(bearer=account, deleted=False).all()
        if not sessions:
            raise NotFoundError("No sessions associated to account were found.")
        return sessions

    @classmethod
    def decode_raw(cls, request: Request) -> dict:
        """
        Decodes JWT token from client cookie into a python dict.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session_dict

        Raises:
            JWTDecodeError
        """
        cookie = request.cookies.get(
            f"{security_config.SESSION_PREFIX}_{cls.__name__.lower()[:7]}"
        )
        try:
            if not cookie:
                raise JWTDecodeError("Session token not provided or expired.", 401)
            else:
                return jwt.decode(
                    cookie,
                    security_config.PUBLIC_SECRET or security_config.SECRET,
                    security_config.SESSION_ENCODING_ALGORITHM,
                )
        except DecodeError as e:
            raise JWTDecodeError(str(e))

    @classmethod
    async def decode(cls, request: Request):
        """
        Decodes session JWT from client cookie to a Sanic Security session.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session

        Raises:
            JWTDecodeError
            NotFoundError
        """
        try:
            decoded_raw = cls.decode_raw(request)
            decoded_session = (
                await cls.filter(id=decoded_raw["id"]).prefetch_related("bearer").get()
            )
        except DoesNotExist:
            raise NotFoundError("Session could not be found.")
        return decoded_session

    class Meta:
        abstract = True


class VerificationSession(Session):
    """
    Used for a client verification method that requires some form of code, challenge, or key.

    Attributes:
        attempts (int): The amount of incorrect times a user entered a code not equal to this verification sessions code.
        code (str): Used as a secret key that would be sent via email, text, etc to complete the verification challenge.
    """

    attempts: int = fields.IntField(default=0)
    code: str = fields.CharField(max_length=10, default=get_code, null=True)

    async def check_code(self, code: str) -> None:
        """
        Checks if code passed is equivalent to the session code.

        Args:
            code (str): Code being cross-checked with session code.

        Raises:
            ChallengeError
            MaxedOutChallengeError
        """
        if self.code != code.upper():
            if self.attempts < security_config.MAX_CHALLENGE_ATTEMPTS:
                self.attempts += 1
                await self.save(update_fields=["attempts"])
                raise ChallengeError(
                    "Your code does not match verification session code."
                )
            else:
                raise MaxedOutChallengeError()
        else:
            logger.info(
                f"Client has completed verification session {self.id} challenge."
            )
            await self.deactivate()

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        raise NotImplementedError

    class Meta:
        abstract = True


class TwoStepSession(VerificationSession):
    """
    Validates a client using a code sent via email or text.
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        return await TwoStepSession.create(
            **kwargs,
            ip=get_ip(request),
            bearer=account,
            expiration_date=get_expiration_date(
                security_config.TWO_STEP_SESSION_EXPIRATION
            ),
        )

    class Meta:
        table = "two_step_session"


class CaptchaSession(VerificationSession):
    """
    Validates a client with a captcha challenge.
    """

    @classmethod
    async def new(cls, request: Request, **kwargs):
        return await CaptchaSession.create(
            **kwargs,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.CAPTCHA_SESSION_EXPIRATION
            ),
        )

    def get_image(self) -> HTTPResponse:
        """
        Retrieves captcha image file.

        Returns:
            captcha_image
        """
        image = ImageCaptcha(190, 90, fonts=[security_config.CAPTCHA_FONT])
        with BytesIO() as output:
            image.generate_image(self.code).save(output, format="JPEG")
            return raw(output.getvalue(), content_type="image/jpeg")

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    """
    Used to authenticate and identify a client.

    Attributes:
        refresh_expiration_date (bool): Date and time the session can no longer be refreshed.
        requires_second_factor (bool): Determines if session requires a second factor.
        is_refresh (bool): Will only be true once when instantiated during refresh of expired session.
    """

    refresh_expiration_date: datetime.datetime = fields.DatetimeField(null=True)
    requires_second_factor: bool = fields.BooleanField(default=False)
    is_refresh: bool = False

    def validate(self) -> None:
        """
        Raises an error with respect to session state.

        Raises:
            DeletedError
            ExpiredError
            DeactivatedError
            SecondFactorRequiredError
        """
        super().validate()
        if self.requires_second_factor:
            raise SecondFactorRequiredError()

    async def refresh(self, request: Request):
        """
        Refreshes session if expired and within refresh date.

        Raises:
            DeletedError
            ExpiredError
            DeactivatedError
            SecondFactorRequiredError
            NotExpiredError

        Returns:
            session
        """
        try:
            self.validate()
            raise NotExpiredError()
        except ExpiredError as e:
            if (
                self.refresh_expiration_date
                and datetime.datetime.now(datetime.timezone.utc)
                <= self.refresh_expiration_date
            ):
                self.active = False
                await self.save(update_fields=["active"])
                logger.info(f"Client has refreshed authentication session {self.id}.")
                return await self.new(request, self.bearer, True)
            else:
                raise e

    @classmethod
    async def new(
        cls, request: Request, account: Account = None, is_refresh=False, **kwargs
    ):
        authentication_session = await AuthenticationSession.create(
            **kwargs,
            bearer=account,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.AUTHENTICATION_SESSION_EXPIRATION
            ),
            refresh_expiration_date=get_expiration_date(
                security_config.AUTHENTICATION_REFRESH_EXPIRATION
            ),
        )
        authentication_session.is_refresh = is_refresh
        return authentication_session

    class Meta:
        table = "authentication_session"


class Role(BaseModel):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be separated via comma + space and in wildcard format (printer:query, dashboard:info,delete).
    """

    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.CharField(max_length=255, null=True)

    def validate(self) -> None:
        raise NotImplementedError()

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions,
        }
