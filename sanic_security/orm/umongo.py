import datetime as dt
import uuid
from types import SimpleNamespace

from bson import objectid
import bson

import phonenumbers

from marshmallow import ValidationError
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse
from umongo import Document, EmbeddedDocument, fields, validate, pre_load, MixinDocument
from umongo.frameworks.motor_asyncio import MotorAsyncIOReference
from umongo.exceptions import NotCreatedError
from pymongo.errors import DuplicateKeyError

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

app = Sanic.get_app()
if not app.config.get('LAZY_UMONGO', None):
    from umongo.frameworks import MotorAsyncIOInstance
    app.config.LAZY_UMONGO = MotorAsyncIOInstance()
instance = app.config.get('LAZY_UMONGO')


# ensure indexes
@app.listener('before_server_start')
async def init(sanic):
    await setup_indexes()


@instance.register
class BaseMixin(MixinDocument):
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): Renders the model find_oneable without removing from the database.
    """

    id: uuid.UUID = fields.ObjectIdField()
    date_created: dt.datetime = fields.DateTimeField(auto_now_add=True)
    date_updated: dt.datetime = fields.DateTimeField(auto_now=True)
    deleted: bool = fields.BooleanField(load_default=False)

    def validate(self) -> None:
        """
        Raises an error with respect to state.

        Raises:
            SecurityError
        """
        raise NotImplementedError()

    async def verify(self) -> None:
        self.verified = True
        await self.commit()

    async def json(self, cls) -> dict:
        _ma = cls.schema.as_marshmallow_schema()
        schema = _ma()
        return schema.dump(self)

    class Meta:
        abstract = True


@instance.register
class Account(Document, BaseMixin):
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

    username = fields.StringField(required=False, unique=True, validate=[validate.Regexp(r"^[A-Za-z0-9 @_-]{3,32}$")])
    email: str = fields.EmailField(required=True, unique=True, allow_none=False)
    password: str = fields.StringField(required=True, validate=[validate.Length(max=512)], allow_none=False)
    phone: str = fields.StringField(required=False,
                                    validate=[validate.Length(max=11, min=10),],
                                    load_default=None, unique=True)
    created_at: dt.datetime = fields.DateTimeField(allow_none=False, load_default=lambda: dt.datetime.utcnow())
    last_login_at: dt.datetime = fields.DateTimeField(null=True)
    current_login_at: dt.datetime = fields.DateTimeField(null=True)
    confirmed_at: dt.datetime = fields.DateTimeField(null=True)
    last_login_ip: str = fields.StringField(validate=[validate.Length(max=60)], null=True)
    current_login_ip: str = fields.StringField(validate=[validate.Length(max=60)], null=True)
    disabled: bool = fields.BooleanField(load_default=False)
    verified: bool = fields.BooleanField(load_default=False)
    roles = fields.ListField(fields.ReferenceField('Role', fetch=True), null=True, fetch=True) 

    @pre_load
    def clean(self, data, many, **kwargs):
        if 'phone' in data:
            try:
                _phone = phonenumbers.parse(data['phone'], "US") # Default to US
                if not phonenumbers.is_possible_number(_phone):
                    raise ValidationError(f"Value '{data['phone']}' is not a valid phone number")
            except Exception:
                raise ValidationError(f"Value '{data['phone']}' is not a valid phone number")
        
        return data

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

    async def json(self) -> dict:
        _ma = Account().schema.as_marshmallow_schema()
        schema = _ma(exclude=['password'])
        return schema.dump(self)

    @staticmethod
    async def new(**kwargs):
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

        logger.debug(f"New user requested: {kwargs}")
        try:
            _account = await Account(**kwargs).commit()
        except DuplicateKeyError as e:
            logger.info(f'Tried to create a duplicate key! {e}')
            raise AccountError(e.message)
        except ValidationError as e:
            logger.info(f'Tried to create an invalid account! {e}')
            raise AccountError(e.messages, code=400)
        except Exception as e:
            logger.error(f'Generic Exception! {e}')
            raise AccountError(str(e))

        return await Account.find_one({'id': _account.inserted_id, 'deleted': False})

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
            account = await Account.find_one({'id': id})
        if not account:
            raise NotFoundError("Lookup returned no matching user")
        elif not account.roles:
            return []

        roles = [await role.fetch() for role in account.roles]
        return roles

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
        account = await id.fetch()
        logger.debug(f'Fetched account = {account}')
        if not account.pk:
            if not id:
                raise AccountError('Must provide Account object or pass `id` parameter!')
            account = await Account.find_one({'id': id})
        if not account:
            raise NotFoundError("Lookup requested by no identifier provided")
        if account.roles:
            account.roles.append(role)
        else:
            account.roles = [role]
        await account.commit()
        return account

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
                account = await Account.find_one({'email': email, 'deleted': False})
                logger.debug(f"Lookup user identified by email: {email}")
            elif username:
                account = await Account.find_one({'username': username, 'deleted': False})
                logger.debug(f"Lookup user identified by username: {username}")
            elif phone:
                account = await Account.find_one({'phone': phone, 'deleted': False})
                logger.debug(f"Lookup user identified by phone: {phone}")
            elif id:
                account = await Account.find_one({'id': id, 'deleted': False})
                logger.debug(f"Lookup user identified by id: {id}")
            else:
                raise NotFoundError("Lookup requested by no identifier provided")
            if not account:
                raise NotCreatedError

            logger.debug(f"Account Found: {account}")
            return account
        except NotCreatedError:
            raise NotFoundError("Account with this identifier does not exist.")


@instance.register
class Session(BaseMixin, MixinDocument):
    """
    Used for client identification and verification. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Date and time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client creating session.
        bearer (ForeignKeyRelation[Account]): Account associated with this session.
        ctx (SimpleNamespace): Store whatever additional information you need about the session. Fields stored will be encoded.
    """

    expiration_date: dt.datetime = fields.DateTimeField(null=True)
    refresh_expiration_date: dt.datetime = fields.DateTimeField(null=True)
    active: bool = fields.BooleanField(load_default=True)
    ip: str = fields.StringField(max_length=16)
    bearer = fields.ReferenceField('Account', fetch=True)
    ctx = SimpleNamespace()

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

    #@staticmethod
    async def lookup(cls, id: str = None):
        return await cls.find_one({'id': objectid.ObjectId(id)})

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
            and dt.datetime.now() >= self.expiration_date
            #and dt.datetime.now(dt.timezone.utc) >= self.expiration_date
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
            logger.debug(f'Decoded_Raw: {decoded_raw}')
            decoded_session = (
                await cls.find_one({'id': objectid.ObjectId(decoded_raw["id"])})
            )
            if not decoded_session:
                raise NotCreatedError
        except NotCreatedError:
            raise NotFoundError("Session could not be found.")
        if isinstance(decoded_session.bearer, str) or isinstance(decoded_session.bearer, MotorAsyncIOReference):
            return decoded_session, await decoded_session.bearer.fetch()
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
            JWTDecodeError
            NotFoundError
        """
        try:
            session.active = False
            deactivated_session = (
                #TODO: Should probably be removing old sessions, not just setting inactive
                await session.commit()
            )
            if not deactivated_session:
                raise NotCreatedError
        except NotCreatedError:
            raise NotFoundError("Session could not be found.")
        return session

    async def json(self) -> dict:
        _ma = Session().schema.as_marshmallow_schema()
        schema = _ma()
        return schema.dump(self)

    class Meta:
        abstract = True


@instance.register
class VerificationSession(Session, BaseMixin, MixinDocument):
    """
    Used for a client verification method that requires some form of code, challenge, or key.

    Attributes:
        attempts (int): The amount of incorrect times a user entered a code not equal to this verification sessions code.
        code (str): Used as a secret key that would be sent via email, text, etc to complete the verification challenge.
    """

    attempts: int = fields.IntField(load_default=0)
    code: str = fields.StringField(max_length=10, load_default=get_code, null=True)

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
                await self.commit()
                raise ChallengeError("The value provided does not match.")
            else:
                logger.warning(
                    f"Client ({self.bearer.pk}/{get_ip(request)}) has maxed out on session challenge attempts"
                )
                raise MaxedOutChallengeError()
        else:
            self.active = False
            await self.commit()

    async def lookup(cls, id: str = None):
        return await cls.find_one({'id': objectid.ObjectId(id)})

    class Meta:
        abstract = True
        allow_inheritance = True


@instance.register
class TwoStepSession(VerificationSession, Document):
    """
    Validates a client using a code sent via email or text.
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        _session = await TwoStepSession(
            ip = get_ip(request),
            bearer = account['id'],
            expiration_date = get_expiration_date(
                security_config.SANIC_SECURITY_TWO_STEP_SESSION_EXPIRATION
            ),
        ).commit()
        logger.debug(f"TwoStepSession Created: {_session}")
        new_session = await TwoStepSession.find_one({'id': _session.inserted_id, 'deleted': False})
        return new_session

    async def lookup(cls, id: str = None):
        return await cls.find_one({'id': objectid.ObjectId(id)})


@instance.register
class CaptchaSession(Document, VerificationSession, Session):
    """
    Validates a client with a captcha challenge.
    """

    @classmethod
    async def new(cls, request: Request, **kwargs):
        _captcha_session = await CaptchaSession(
            **kwargs,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_CAPTCHA_SESSION_EXPIRATION
            ),
        ).commit()
        return await CaptchaSession.find_one({'id': _captcha_session.inserted_id})

    async def lookup(cls, id: str = None):
        return await cls.find_one({'id': objectid.ObjectId(id)})

    class Meta:
        table = "captcha_session"


@instance.register
class AuthenticationSession(Document, VerificationSession, Session, BaseMixin):
    """
    Used to authenticate and identify a client.
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        _auth_session = await AuthenticationSession(
            **kwargs,
            bearer=account,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION
            ),
            refresh_expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION * 2
            ),
        ).commit()
        return await AuthenticationSession.find_one({'id': _auth_session.inserted_id})

    async def lookup(cls, id: str = None):
        return await cls.find_one({'id': objectid.ObjectId(id)})


@instance.register
class Role(Document, BaseMixin):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be separated via comma and in wildcard format (printer:query, printer:query,delete).
    """

    name: str = fields.StringField(max_length=255, allow_none=False, unique=True)
    description: str = fields.StringField(required=False, max_length=255, allow_none=True)
    permissions: str = fields.StringField(required=False, max_length=255, allow_none=True)

    def __repr__(self):
        """Represent instance as a unique string."""
        return f'<Role({self.name})>'

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
            role = await Role.find_one({'name': name, 'deleted': False})
            if role:
                return role
            raise NotCreatedError
        except NotCreatedError:
            raise NotFoundError("Role with this name does not exist.")

    @staticmethod
    async def new(**kwargs):
        new_role = await Role(**kwargs).commit()
        return await Role.find_one({'id': new_role.inserted_id, 'deleted': False})


async def setup_indexes():
    """
    Must be called, once, for each model we have indexes on (including default `unique`),
     for uMongo to create/update them

    """
    try:
        await Account.ensure_indexes()
    except DuplicateKeyError as e:
        logger.info('Indexes for Account table already setup')
    except Exception as e:
        if 'An equivalent index already exists' in e:
            logger.info('Indexes for Account table already setup')
    try:
        await Role.ensure_indexes()
    except DuplicateKeyError as e:
        logger.info('Indexes for Account table already setup')
    except Exception as e:
        if 'An equivalent index already exists' in e:
            logger.info('Indexes for Role table already setup')
