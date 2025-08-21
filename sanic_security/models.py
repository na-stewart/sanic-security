import base64
import datetime
import logging
import re
import uuid
from typing import Union

import jwt
from jwt import DecodeError
from sanic.request import Request
from sanic.response import HTTPResponse
from tortoise import fields, Model
from tortoise.exceptions import DoesNotExist, ValidationError
from tortoise.validators import RegexValidator

from sanic_security.configuration import config
from sanic_security.exceptions import *
from sanic_security.utils import (
    get_ip,
    get_code,
    get_expiration_date,
    image_generator,
    audio_generator,
    is_expired,
)

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
        id (str): Primary key of model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): Renders the model filterable without removing from the database.
    """

    id: str = fields.CharField(
        pk=True, max_length=36, default=lambda: str(uuid.uuid4())
    )
    date_created: datetime.datetime = fields.DatetimeField(auto_now_add=True)
    date_updated: datetime.datetime = fields.DatetimeField(auto_now=True)
    deleted: bool = fields.BooleanField(default=False)

    def validate(self) -> None:
        """
        Raises an error with respect to model's state.

        Raises:
            SecurityError
        """
        raise NotImplementedError

    @property
    def json(self) -> dict:
        """
        A JSON serializable dict to be used in a request or response.

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
        raise NotImplementedError

    class Meta:
        abstract = True


class Account(BaseModel):
    """
    Contains all identifiable user information.

    Attributes:
        username (str): Public identifier.
        email (str): Private identifier and can be used for verification.
        phone (str): Mobile phone number with country code included and can be used for verification. Can be null or empty.
        password (str): Password of account for user protection, must be hashed via Argon2.
        oauth_id (str): Identifier associated with an OAuth authorization flow.
        disabled (bool): Renders the account unusable but available.
        verified (bool): Renders the account unusable until verified via two-step verification or other method.
        roles (ManyToManyRelation[Role]): Roles associated with this account.
    """

    username: str = fields.CharField(
        unique=config.ALLOW_LOGIN_WITH_USERNAME,
        max_length=32,
    )
    email: str = fields.CharField(
        unique=True,
        max_length=255,
        validators=[
            RegexValidator(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", re.I)
        ],
    )
    phone: str = fields.CharField(
        unique=True,
        max_length=20,
        null=True,
        validators=[
            RegexValidator(r"^(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$", re.I)
        ],
    )
    password: str = fields.CharField(max_length=255)
    oauth_id: str = fields.CharField(unique=True, null=True, max_length=255)
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
            raise UnverifiedError
        elif self.disabled:
            raise DisabledError

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
            return await Account.filter(email=email.lower(), deleted=False).get()
        except (DoesNotExist, ValidationError):
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
            return await Account.filter(username=username, deleted=False).get()
        except (DoesNotExist, ValidationError):
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
            if config.ALLOW_LOGIN_WITH_USERNAME:
                account = await Account.get_via_username(credential)
            else:
                raise e
        return account

    @staticmethod
    async def get_via_header(request: Request):
        """
         Retrieve an account via the basic authorization header.

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
        Retrieve an account via a phone number.

        Args:
            phone (str): Phone number associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            return await Account.filter(phone=phone, deleted=False).get()
        except (DoesNotExist, ValidationError):
            raise NotFoundError("Account with this phone number does not exist.")


class Session(BaseModel):
    """
    Used for client identification and verification. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Date and time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client instantiating session.
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
            raise DeactivatedError
        elif is_expired(self.expiration_date):
            raise ExpiredError

    async def deactivate(self) -> None:
        """
        Renders session deactivated and therefor unusable.

        Raises:
            DeactivatedError
        """
        if self.active:
            self.active = False
            await self.save(update_fields=["active"])
        else:
            raise DeactivatedError("Session is already deactivated.", 403)

    def encode(self, response: HTTPResponse) -> None:
        """
        Transforms session into JWT and then is stored in a cookie.

        Args:
            response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
        """
        encoded_session = jwt.encode(
            {
                "id": self.id,
                "date_created": str(self.date_created),
                "expiration_date": str(self.expiration_date),
                "bearer": self.bearer.id if isinstance(self.bearer, Account) else None,
                "ip": self.ip,
            },
            config.SECRET,
            config.SESSION_ENCODING_ALGORITHM,
        )
        response.cookies.add_cookie(
            f"{config.SESSION_PREFIX}_{self.__class__.__name__[:7].lower()}",
            str(encoded_session),
            httponly=config.SESSION_HTTPONLY,
            samesite=config.SESSION_SAMESITE,
            secure=config.SESSION_SECURE,
            domain=config.SESSION_DOMAIN,
            expires=getattr(self, "refresh_expiration_date", self.expiration_date),
        )

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": self.bearer.id if isinstance(self.bearer, Account) else None,
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
        **kwargs: dict[str, Union[int, str, bool, float, list, dict]],
    ):
        """
        Creates session with pre-set values.

        Args:
            request (Request): Sanic request parameter.
            account (Account): Account being associated to the session.
            **kwargs (Union[int, str, bool, float, list, dict]): Extra arguments applied during session creation.

        Returns:
            session
        """
        raise NotImplementedError

    @classmethod
    async def get_associated(cls, account: Account):
        """
        Retrieves sessions associated to an account.

        Args:
            account (Account): Account associated with sessions being retrieved.

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
        Decodes session JWT token from client cookie into a python dict.

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session_dict

        Raises:
            JWTDecodeError
        """
        cookie = request.cookies.get(
            f"{config.SESSION_PREFIX}_{cls.__name__[:7].lower()}"
        )
        try:
            if not cookie:
                raise JWTDecodeError
            else:
                return jwt.decode(
                    cookie,
                    config.PUBLIC_SECRET or config.SECRET,
                    config.SESSION_ENCODING_ALGORITHM,
                )
        except DecodeError as e:
            raise JWTDecodeError(str(e))

    @classmethod
    async def decode(
        cls,
        request: Request,
        raw: dict = None,
        **kwargs: Union[int, str, bool, float],
    ):
        """
        Decodes session JWT token from client cookie into a session model.

        Args:
            request (Request): Sanic request parameter.
            raw (Request): Decoded JWT token provided by the client, include only for optimization purposes.
            **kwargs (Union[int, str, bool, float]): Extra filter arguments applied during session decoding.


        Returns:
            session

        Raises:
            JWTDecodeError
            NotFoundError
        """
        try:
            decoded_raw = raw or cls.decode_raw(request)
            decoded_session = (
                await cls.filter(**kwargs, id=decoded_raw["id"], deleted=False)
                .prefetch_related("bearer")
                .get()
            )
            request.ctx.session = decoded_session
        except DoesNotExist:
            raise NotFoundError("Session could not be found.")
        return decoded_session

    class Meta:
        abstract = True


class VerificationSession(Session):
    """
    Used for client verification challenges that require some form of code or key.

    Attributes:
        attempts (int): The amount of times a user entered a code not equal to this verification sessions code.
        code (str): A secret key that would be sent via email, text, etc.
    """

    attempts: int = fields.IntField(default=0)
    code: str = fields.CharField(max_length=6, null=True)

    async def check_code(self, code: str) -> None:
        """
        Checks if code passed is equivalent to the session code.

        Args:
            code (str): Code being cross-checked with session code.

        Raises:
            ChallengeError
            MaxedOutChallengeError
        """
        if not code or self.code != code.upper():
            self.attempts += 1
            if self.attempts < config.MAX_CHALLENGE_ATTEMPTS:
                await self.save(update_fields=["attempts"])
                raise ChallengeError(
                    "Your code does not match verification session code."
                )
            else:
                raise MaxedOutChallengeError
        else:
            await self.deactivate()

    @classmethod
    async def new(
        cls,
        request: Request,
        account: Account,
        **kwargs: Union[int, str, bool, float, list, dict],
    ):
        raise NotImplementedError

    class Meta:
        abstract = True


class TwoStepSession(VerificationSession):
    """
    Validates client using a code sent via email or text.

    Attributes:
        tag (str): Label used to distinguish sessions for specific purposes.
    """

    tag: str = fields.CharField(max_length=20)

    @classmethod
    async def new(
        cls,
        request: Request,
        account: Account,
        **kwargs: Union[int, str, bool, float, list, dict],
    ):
        return await cls.create(
            **kwargs,
            ip=get_ip(request),
            bearer=account,
            expiration_date=get_expiration_date(config.TWO_STEP_SESSION_EXPIRATION),
            code=get_code(True),
        )

    class Meta:
        table = "two_step_session"


class CaptchaSession(VerificationSession):
    """Validates client with a captcha challenge via image or audio."""

    @classmethod
    async def new(
        cls,
        request: Request,
        **kwargs: Union[int, str, bool, float, list, dict],
    ):
        return await cls.create(
            **kwargs,
            ip=get_ip(request),
            code=get_code(),
            expiration_date=get_expiration_date(config.CAPTCHA_SESSION_EXPIRATION),
        )

    def get_image(self) -> bytes:
        """
        Retrieves captcha image data.

        Returns:
            captcha_image
        """
        return image_generator.generate(self.code, "jpeg").getvalue()

    def get_audio(self) -> bytes:
        """
        Retrieves captcha audio data.

        Returns:
            captcha_audio
        """
        return bytes(audio_generator.generate(self.code))

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    """
    Used to authenticate and identify a client.

    Attributes:
        refresh_expiration_date (datetime): Date and time the session can no longer be refreshed.
        requires_second_factor (bool): Determines if session requires a second factor.
        user_agent (bool): Identifies client application, operating system, vendor, and/or version.
        is_refresh (bool): Will only be true once when instantiated during the refresh of expired session.
    """

    refresh_expiration_date: datetime.datetime = fields.DatetimeField(null=True)
    requires_second_factor: bool = fields.BooleanField(default=False)
    user_agent: str = fields.CharField(max_length=255, null=True)
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
            raise SecondFactorRequiredError

    async def refresh(self, request: Request):
        """
        Refreshes session if within refresh date.

        Args:
            request (Request): Sanic request parameter.

        Raises:
            ExpiredError

        Returns:
            session
        """
        if self.active and not is_expired(self.refresh_expiration_date):
            await self.deactivate()
            logging.info(
                f"Client {get_ip(request)} has refreshed authentication session {self.id}."
            )
            return await self.new(request, self.bearer)
        else:
            raise ExpiredError

    @classmethod
    async def new(
        cls,
        request: Request,
        account: Account = None,
        **kwargs: Union[int, str, bool, float, list, dict],
    ):
        authentication_session = await cls.create(
            **kwargs,
            bearer=account,
            ip=get_ip(request),
            user_agent=request.headers.get("user-agent"),
            expiration_date=get_expiration_date(
                config.AUTHENTICATION_SESSION_EXPIRATION
            ),
            refresh_expiration_date=get_expiration_date(
                config.AUTHENTICATION_REFRESH_EXPIRATION
            ),
        )
        return authentication_session

    class Meta:
        table = "authentication_session"


class Role(BaseModel):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (list[str]): Permissions of the role, must in wildcard format (printer:query, dashboard:info,delete).
    """

    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: list[str] = fields.JSONField(null=True)

    def validate(self) -> None:
        raise NotImplementedError

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
