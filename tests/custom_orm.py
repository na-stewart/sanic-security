import datetime as dt
import uuid
from types import SimpleNamespace

import re

from bson import objectid
import json as js

import phonenumbers

from marshmallow import ValidationError
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse

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

class BaseMixin():
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): Renders the model find_oneable without removing from the database.
    """

    id: str = None
    pk: str = None
    date_created: dt.datetime = None
    date_updated: dt.datetime = None
    deleted: bool = False

    def validate(self) -> None:
        """
        Raises an error with respect to state.

        Raises:
            SecurityError
        """
        raise NotImplementedError()

    async def verify(self) -> None:
        self.verified = True

    async def json(self) -> dict:
        return js.dumps(vars(self))
    
    def __init__(self, **kwargs):
        for arg in kwargs:
            setattr(self, arg, kwargs[arg])

    class Meta:
        abstract = True


class Account(BaseMixin):
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

    db = []

    username: str = None
    email: str = None
    password: str = None
    phone: str = None
    created_at: dt.datetime = lambda: dt.datetime.utcnow()
    last_login_at: dt.datetime = None
    current_login_at: dt.datetime = None
    confirmed_at: dt.datetime = None
    last_login_ip: str = None
    current_login_ip: str = None
    disabled: bool = False
    verified: bool = True
    roles: list = list([])

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
        _data: dict = dict([])

        for _var in vars(self):
            if type(getattr(self, _var)) not in [str, bool, list, tuple, dict, int]:
                _data[_var] = await _var.json()
            elif type(getattr(self, _var)) is list:
                _list = []
                for _sub_var in getattr(self, _var):
                    _list.append(await _sub_var.json())
                _data[_var] = _list
            else:
                _data[_var] = getattr(self, _var)

        return js.dumps(_data)

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

        if 'phone' in kwargs:
            try:
                _phone = phonenumbers.parse(kwargs['phone'], "US") # Default to US
                if not phonenumbers.is_possible_number(_phone):
                    raise ValidationError(f"Value '{kwargs['phone']}' is not a valid phone number")
            except Exception:
                raise ValidationError(f"Value '{kwargs['phone']}' is not a valid phone number")
        else:
            raise ValidationError(f"Value 'phone' is missing")
        if 'username' in kwargs:
            username_re = '^[A-Za-z0-9 @_-]{3,32}$'
            if not re.search(username_re, kwargs['username']):
                raise ValidationError(f"Value '{kwargs['username']}' is not a valid username")
        else:
            raise ValidationError(f"Value 'username' is missing")
        if 'email' in kwargs:
            email_re = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            if not re.search(email_re, kwargs['email']):
                raise ValidationError(f"Value '{kwargs['email']}' is not a valid email")
        else:
            raise ValidationError(f"Value 'email' is missing")

        logger.debug(f"New user requested: {kwargs}")
        user = None
        try:
            for account in Account.db:
                if kwargs['email'] == account.email:
                    logger.info(f'Tried to create a duplicate key! {e}')
                    raise AccountError(f"Account with email {kwargs['email']} already exists!", 401)

            _id = str(uuid.uuid4())
            user = Account(username = kwargs['username'], password = kwargs['password'],
                           email = kwargs['email'], phone = kwargs['phone'], roles = [],
                           id = _id, verified = kwargs['verified'], disabled = kwargs.get('disabled', False),
                           pk = _id
            )
            Account.db.append(user)

            """
            except ValidationError as e:
                logger.info(f'Tried to create an invalid account! {e}')
                raise AccountError(e.messages, code=400)
            """
        except Exception as e:
            logger.error(f'Generic Exception! {e}')
            raise AccountError(str(e), 400)

        return user


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

        account = None
        roles = []

        if not hasattr(self, 'id'):
            logger.debug(f"searching for user: {id}")
            for user in Account.db:
                if self == user.id or id == user.id:
                    account = user
                    break
        else:
            account = self

        if not account:
            raise NotFoundError("Lookup returned no matching user")

        if not account.roles or account.roles == roles or (len(account.roles) == 1 and not account.roles[0]):
            return roles

        for user_role in account.roles:
            for db_role in Role.db:
                if user_role.name == db_role.name:
                    roles.append(db_role)

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

        account = self 
        if not account.id:
            if not id:
                raise AccountError('Must provide Account object or pass `id` parameter!', 401)
            for user in self.db:
                if id == user.id:
                    account = user
                    break
        if not account:
            raise NotFoundError("Lookup requested by no identifier provided")

        logger.debug(f'Adding role {role} to Account {account.email}')
        if account.roles:
            account.roles.append(role)
        else:
            account.roles = [role]
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
            if not account:
                for user in Account.db:
                    if id == user.id:
                        account = user
                        logger.debug(f"Lookup user identified by id: {id}")
                        break
                    if email == user.email:
                        account = user
                        logger.debug(f"Lookup user identified by email: {email}")
                        break
                    elif username == user.username:
                        account = user
                        logger.debug(f"Lookup user identified by username: {username}")
                        break
                    elif phone == user.phone:
                        account = user
                        logger.debug(f"Lookup user identified by phone: {phone}")
                        break

                if not account:
                    raise NotFoundError('No account found matching provided identifiers')

            logger.debug(f"Lookup Account Found: {account}")
            return account
        except NotFoundError:
            raise NotFoundError("Account with this identifier does not exist.")


class Session(BaseMixin):
    """
    Used for client identification and verification. Base session model that all session models derive from.

    Attributes:
        expiration_date (datetime): Date and time the session expires and can no longer be used.
        active (bool): Determines if the session can be used.
        ip (str): IP address of client creating session.
        bearer (ForeignKeyRelation[Account]): Account associated with this session.
        ctx (SimpleNamespace): Store whatever additional information you need about the session. Fields stored will be encoded.
    """

    db = []

    expiration_date: dt.datetime = None
    refresh_expiration_date: dt.datetime = None
    active: bool = True
    ip: str = None
    bearer = None
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

    @classmethod
    async def lookup(cls, id: str = None):
        """
        Looks up a session based upon its ID

        Args:
            id (string): Session Identifier
        
        Returns:
            session, session bearer

        Raises:
            NotFoundError
        """

        found_session = None
        for _session in cls.db:
            if _session.id == id:
                found_session = _session

        if not found_session:
            raise NotFoundError("Session could not be found.")

        if isinstance(found_session.bearer, str):
            _bearer = await Account.lookup(id=found_session.bearer)
            return found_session, _bearer

        return found_session, found_session.bearer

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
            if not session.id:
                raise NotFoundError
        except NotFoundError:
            raise NotFoundError("Session could not be found.")
        return session

    async def json(self) -> dict:
        _data: dict = dict([])

        for _var in vars(self):
            if type(_var) not in [str, list, tuple, dict, int]:
                logger.debug(f"VAR '{_var}' is type '{type(_var)}")
                _data[_var] = await _var.json()
            else:
                _data[_var] = _var

        return js.dumps(_data)
    
    def __init__(self, **kwargs):
        for arg in kwargs:
            setattr(self, arg, kwargs[arg])

    """
    class Meta:
        abstract = True
    """

    def __str__(self):
        return 'fuck'


class VerificationSession(Session, BaseMixin):
    """
    Used for a client verification method that requires some form of code, challenge, or key.

    Attributes:
        attempts (int): The amount of incorrect times a user entered a code not equal to this verification sessions code.
        code (str): Used as a secret key that would be sent via email, text, etc to complete the verification challenge.
    """

    db: list = list([])

    attempts: int = 0
    code: str = get_code()

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
                raise ChallengeError("The value provided does not match.")
            else:
                logger.warning(
                    f"Client ({self.bearer.pk}/{get_ip(request)}) has maxed out on session challenge attempts"
                )
                raise MaxedOutChallengeError()
        else:
            self.active = False

    class Meta:
        abstract = True
        allow_inheritance = True


class TwoStepSession(VerificationSession):
    """
    Validates a client using a code sent via email or text.
    """

    db: list = list([])

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        _id = str(uuid.uuid4())
        new_session = TwoStepSession(
            id=_id,
            pk=_id,
            ip = get_ip(request),
            bearer = account.id,
            expiration_date = get_expiration_date(
                security_config.SANIC_SECURITY_TWO_STEP_SESSION_EXPIRATION
            ),
        )
        #Session.db.append(new_session)
        cls.db.append(new_session)
        logger.debug(f"TwoStepSession Created: {new_session}")

        return new_session


class CaptchaSession(VerificationSession, Session):
    """
    Validates a client with a captcha challenge.
    """

    db: list = list([])

    @classmethod
    async def new(cls, request: Request, **kwargs):
        _id = str(uuid.uuid4())
        new_captcha_session = CaptchaSession(
            **kwargs,
            id=_id,
            pk=_id,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_CAPTCHA_SESSION_EXPIRATION
            ),
        )
        #Session.db.append(new_captcha_session)
        cls.db.append(new_captcha_session)
        return new_captcha_session

    class Meta:
        table = "captcha_session"


class AuthenticationSession(VerificationSession, Session, BaseMixin):
    """
    Used to authenticate and identify a client.
    """

    db: list = []

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        _id = str(uuid.uuid4())
        new_auth_session = AuthenticationSession(
            **kwargs,
            id=_id,
            pk=_id,
            bearer=account,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION
            ),
            refresh_expiration_date=get_expiration_date(
                security_config.SANIC_SECURITY_AUTHENTICATION_SESSION_EXPIRATION * 2
            ),
        )
        #Session.db.append(new_auth_session)
        cls.db.append(new_auth_session)
        return new_auth_session
    
    class Meta:
        abstract = True


class Role(BaseMixin):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be separated via comma and in wildcard format (printer:query, printer:query,delete).
    """

    db: list = []

    id: str = None
    pk: str = None
    name: str = None
    description: str = None
    permissions: str = None

    """
    def __init__(self, **kwargs):
        for arg in kwargs:
            setattr(self, arg, kwargs[arg])
    """

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
            for role in Role.db:
                if name == role.name:
                    return role
            raise NotFoundError("Role with this name does not exist.")
        except NotFoundError:
            raise NotFoundError("Role with this name does not exist.")

    @staticmethod
    async def new(**kwargs):
        try:
            for role in Role.db:
                if kwargs['name'] == role.name:
                    logger.info(f'Tried to create a duplicate key! {e}')
                    raise AccountError(f"Role with name {kwargs['role']} already exists!", 401)

            _id = str(uuid.uuid4())
            new_role = Role(name = kwargs['name'], permissions = kwargs['permissions'],
                        id = _id, pk = _id, description = kwargs['description'])
            Role.db.append(new_role)
            return new_role

        except Exception as e:
            logger.error(f'Generic Exception! {e}')
            raise AccountError(str(e), 400)
