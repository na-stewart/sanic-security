import datetime
from types import SimpleNamespace

from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse
from tortoise import fields, Model
from tortoise.validators import RegexValidator, Validator
from tortoise.exceptions import DoesNotExist, ValidationError
from tortoise.contrib.pydantic import pydantic_model_creator

import re
import phonenumbers

from sanic_security.configuration import config as security_config
from sanic_security.exceptions import *
from sanic_security.utils import get_ip, get_code, get_expiration_date, decode_raw

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


class PhoneNumberValidator(Validator):
    """
    A validator to check a phone number against `phonenumbers` module

    Raises:
        ValidationError
    """
    def __call__(self, value: str):
        try:
            _phone = phonenumbers.parse(value, "US") # Default to US
            if phonenumbers.is_possible_number(_phone):
                return True
            else:
                raise ValidationError(f"Value '{value}' is not a valid phone number")
        except Exception:
            raise ValidationError(f"Value '{value}' is not a valid phone number")


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
    
    async def verify(self) -> None:
        self.verified = True
        await self.save(update_fields=["verified"])

    async def json(data) -> dict:
        """
        A JSON serializable dict to be used in a HTTP request or response, catchall for all models.

        Async for uniformity with uMongo ORM, as well as anything custom

        TODO: Should probably be customized to remove sensitive data, like password

        Returns:
           data (json)
        """
        _data = await pydantic_model_creator(data.__class__).from_tortoise_orm(data)
        return _data.json()

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

    username: str = fields.CharField(max_length=32, unique=True, validators=[RegexValidator("^[A-Za-z0-9 @_-]{3,32}$", re.I)])
    email: str = fields.CharField(unique=True, max_length=255, validators=[RegexValidator("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", re.I)])
    phone: str = fields.CharField(unique=True, max_length=14, null=True, validators=[PhoneNumberValidator()])
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

    @staticmethod
    async def lookup(email: str = None, username: str = None, phone: str = None, id: str = None):
        """
        Retrieve an account by primary identifier

        Args (one of):
            email (str): Email associated to account being retrieved.
            username (str): Username associated to account being retrieved.
            phone (str): Phone associated to account being retrieved.
            id (str): Id associated to account being retrieved.

        Returns:
            account

        Raises:
            NotFoundError
        """
        try:
            account = None
            if email:
                account = await Account.filter(email=email, deleted=False).get()
                logger.debug(f"Lookup user identified by email: {email}")
            elif username:
                account = await Account.filter(username=username, deleted=False).get()
                logger.debug(f"Lookup user identified by username: {username}")
            elif phone:
                account = await Account.filter(phone=phone, deleted=False).get()
                logger.debug(f"Lookup user identified by phone: {phone}")
            elif id:
                account = await Account.filter(id=id, deleted=False).get()
                logger.debug(f"Lookup user identified by id: {id}")
            else:
                raise NotFoundError("Lookup requested by no identifier provided")
            logger.debug(f"Found user: {account}")
            return account
        except DoesNotExist:
            raise NotFoundError("Account with this identifier does not exist.")
        except ValidationError as e:
            # Tortoise-ORM is dumb how it validates even at searching
            # This error will arrive if you submit an invalid pattern validated string,
            #   like an `email@email.com` to a regex that doesn't allow `@` symbols
            raise NotFoundError("Account with this identifier does not exist.")
        except Exception as e:
            logger.critical(f'Generic Error! {e}')
            raise AccountError(str(e), code=400)

    @staticmethod
    async def new(email: str = None, username: str = None,
                  password: str = None, phone: str = None,
                  verified: bool = False, disabled: bool = False,
                  roles: list = []
                 ):
        """
        Abstracted method for the defined ORM to create a new Account entry.

        Args:
            email (str): Email address for new account. MUST BE UNIQUE
            username (str): Username for new account (optional). If provided, MUST BE UNIQUE
            password (str): Password for new account (should already be hashed)
            phone (str): Phone number for new account
            verified (bool): Verification status
            disabled (bool): Disabled status
            roles (list): Roles (list of names of valid Role)

        Returns:
            Account (object)

        Raises:
            AccountError
        """

        try:
            logger.debug("Attempting to Create a New Tortoise User")
            account = await Account.create(
               email=email,
               username=username,
               password=password,
               phone=phone,
               verified=verified,
               disabled=disabled,
            )
            for role in roles:
                await account.roles.add(role)
            logger.debug(f"Successfully Created a New Tortoise User: {account}")
            return account
        except ValidationError as e:
            logger.error(f'Tried to create an invalid account! {e}')
            raise AccountError(e, code=400)
        except Exception as e:
            logger.error(f'Generic Exception! {e}')
            raise AccountError(e.message)

    async def get_roles(self, id = None):
        """
        Returns a list of roles for provided account

        Args:
            id (str): Account ID to return roles for

        Returns:
            roles (list)

        Raises:
            NotFoundError
        """

        account = self
        if not account.pk:
            account = await Account.filter(id=id, deleted=False).prefetch_related("roles").get()
        if not account:
            raise NotFoundError("Lookup returned no matching user")
        elif not account.roles:
            return []

        return account.roles

    async def add_role(self, id = None, role = None):
        """
        Add a role to an existing Account

        Args:
            id (str): ID of account to add a role to. Optional if not used as account property
            role (str): Role to add

        Returns:
            Account

        Raises:
            Account Error
            NotFoundError
        """

        logger.debug(f'Trying to add role: {role} to user {id}')
        account = id
        if not account.id:
            if not id:
                raise AccountError('Must provide Account object or pass `id` parameter!')
            account = await Account.filter(id=id, deleted=False).prefetch_related("roles").get()
        if not account:
            raise NotFoundError("Lookup requested by no identifier provided")

        await account.roles.add(role)
        return account


class Session(BaseModel):
    """
    Used for client identification and verification. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Date and time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client creating session.
        bearer (ForeignKeyRelation[Account]): Account associated with this session.
        ctx (SimpleNamespace): Store whatever additional information you need about the session. Fields stored will be encoded.
    """

    expiration_date: datetime.datetime = fields.DatetimeField(null=True)
    active: bool = fields.BooleanField(default=True)
    ip: str = fields.CharField(max_length=16)
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
            decoded_raw = decode_raw(cls, request)
            decoded_session = (
                await cls.filter(id=decoded_raw["id"]).prefetch_related("bearer").get()
            )
        except DoesNotExist:
            raise NotFoundError("Session could not be found.")
        return decoded_session, decoded_session.bearer

    @classmethod
    async def deactivate(cls, session):
        """
        Sets a session as deactivated/deleted session

        Args:
            request (Request): Sanic request parameter.

        Returns:
            session

        Raises:
            NotFoundError
        """
        # TODO: Should probably be removing old sessions, not just setting inactive
        session.active = False
        await session.save(update_fields=["active"])
        return session

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
        permissions (str): Permissions of the role. Must be separated via comma and in 
                           wildcard format (printer:query, printer:query,delete).
    """

    name: str = fields.CharField(max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.CharField(max_length=255, null=True)

    def validate(self) -> None:
        raise NotImplementedError()

    @staticmethod
    async def lookup(name: str):
        """
        Retrieve a role by its name.

        Args:
            name (str): Role name being retrieved.

        Returns:
            role

        Raises:
            NotFoundError
        """
        try:
            role = await Role.filter(name=name).get()
            return role
        except DoesNotExist:
            raise NotFoundError("Role with this name does not exist.")

    @staticmethod
    async def new(**kwargs):
        return await Role.create(
            **kwargs
        )
