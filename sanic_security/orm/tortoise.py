import datetime
import uuid
from io import BytesIO
from types import SimpleNamespace

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
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2020-present Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
        password (str): Password of account for protection. Must be hashed via Argon.
        disabled (bool): Renders the account unusable but available.
        verified (bool): Renders the account unusable until verified via two-step verification or other method.
        roles (ManyToManyRelation[Role]): Roles associated with this account.
    """

    username: str = fields.CharField(max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role"
    )

    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "disabled": self.disabled,
            "verified": self.verified,
        }

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
        token (uuid): Token stored on the client's browser in a cookie for identification.
        bearer (ForeignKeyRelation[Account]): Account associated with this session.
        ctx (SimpleNamespace): Store whatever additional information you need about the session. Fields stored will be encoded.
    """

    expiration_date: datetime.datetime = fields.DatetimeField(null=True)
    active: bool = fields.BooleanField(default=True)
    ip: str = fields.CharField(max_length=16)
    token: uuid.UUID = fields.UUIDField(unique=True, default=uuid.uuid4, max_length=36)
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", null=True
    )
    ctx = SimpleNamespace()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        """
        Creates session with pre-set values.

        Args:
            request (Request): Sanic request parameter.
            account (Account): Account being associated to the session.
            **kwargs (dict[str, Any]): Extra arguments applied during session creation.

        Returns:
            session
        """
        raise NotImplementedError()

    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": self.bearer.email if isinstance(self.bearer, Account) else None,
            "active": self.active,
        }

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
        elif (
            self.expiration_date
            and datetime.datetime.now(datetime.timezone.utc) >= self.expiration_date
        ):
            raise ExpiredError()
        elif not self.active:
            raise DeactivatedError()

    def encode(self, response: HTTPResponse) -> None:
        """
        Transforms session into JWT and then is stored in a cookie.

        Args:
            response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
        """
        payload = {
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
            "token": str(self.token),
            "ip": self.ip,
            **self.ctx.__dict__,
        }
        cookie = f"{security_config.SANIC_SECURITY_SESSION_PREFIX}_{self.__class__.__name__.lower()[:4]}_session"
        encoded_session = jwt.encode(
            payload, security_config.SANIC_SECURITY_SECRET, security_config.SANIC_SECURITY_SESSION_ENCODING_ALGORITHM
        )
        if isinstance(encoded_session, bytes):
            response.cookies[cookie] = encoded_session.decode()
        elif isinstance(encoded_session, str):
            response.cookies[cookie] = encoded_session
        response.cookies[cookie]["httponly"] = security_config.SANIC_SECURITY_SESSION_HTTPONLY
        response.cookies[cookie]["samesite"] = security_config.SANIC_SECURITY_SESSION_SAMESITE
        response.cookies[cookie]["secure"] = security_config.SANIC_SECURITY_SESSION_SECURE
        if security_config.SANIC_SECURITY_SESSION_EXPIRES_ON_CLIENT and self.expiration_date:
            response.cookies[cookie]["expires"] = self.expiration_date
        if security_config.SANIC_SECURITY_SESSION_DOMAIN:
            response.cookies[cookie]["domain"] = security_config.SANIC_SECURITY_SESSION_DOMAIN

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
            f"{security_config.SANIC_SECURITY_SESSION_PREFIX}_{cls.__name__.lower()[:4]}_session"
        )
        try:
            if not cookie:
                raise JWTDecodeError("Session token not provided.")
            else:
                return jwt.decode(
                    cookie,
                    security_config.SANIC_SECURITY_SECRET
                    if not security_config.SANIC_SECURITY_PUBLIC_SECRET
                    else security_config.SANIC_SECURITY_PUBLIC_SECRET,
                    security_config.SANIC_SECURITY_SESSION_ENCODING_ALGORITHM,
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
                await cls.filter(token=decoded_raw["token"])
                .prefetch_related("bearer")
                .get()
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

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        raise NotImplementedError

    async def check_code(self, request: Request, code: str) -> None:
        """
        Checks if code passed is equivalent to the session code.

        Args:
            code (str): Code being cross-checked with session code.
            request (Request): Sanic request parameter.

        Raises:
            ChallengeError
            MaxedOutChallengeError
        """
        if self.code != code:
            if self.attempts < security_config.SANIC_SECURITY_MAX_CHALLENGE_ATTEMPTS:
                self.attempts += 1
                await self.save(update_fields=["attempts"])
                raise ChallengeError("The value provided does not match.")
            else:
                logger.warning(
                    f"Client ({self.bearer.email}/{get_ip(request)}) has maxed out on session challenge attempts"
                )
                raise MaxedOutChallengeError()
        else:
            self.active = False
            await self.save(update_fields=["active"])

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
                security_config.SANIC_SECURITY_TWO_STEP_SESSION_EXPIRATION
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
                security_config.SANIC_SECURITY_CAPTCHA_SESSION_EXPIRATION
            ),
        )

    def get_image(self) -> HTTPResponse:
        """
        Retrieves captcha image file.

        Returns:
            captcha_image
        """
        image = ImageCaptcha(190, 90)
        with BytesIO() as output:
            image.generate_image(self.code).save(output, format="JPEG")
            return raw(output.getvalue(), content_type="image/jpeg")

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    """
    Used to authenticate and identify a client.
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        return await AuthenticationSession.create(
            **kwargs,
            bearer=account,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION
            ),
            refresh_expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION * 2
            ),
        )


class Role(BaseModel):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be separated via comma and in wildcard format (printer:query, printer:query,delete).
    """

    name: str = fields.CharField(max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.CharField(max_length=255, null=True)

    def validate(self) -> None:
        raise NotImplementedError()

    def json(self) -> dict:
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions,
        }
