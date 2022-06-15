import datetime as dt
import uuid
from io import BytesIO
from types import SimpleNamespace

import jwt
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, raw
from umongo import Document, EmbeddedDocument, fields, validate, post_load, MixinDocument
from umongo.exceptions import NotCreatedError

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
        deleted (bool): Renders the model filterable without removing from the database.
    """

    _id: uuid.UUID = fields.ObjectIdField()
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

    _id: uuid.UUID = fields.ObjectIdField()
    username = fields.StringField(required=True, unique=True)
    email: str = fields.EmailField(required=True, unique=True, null=False, metadata={"required": True}, marshmallow_required=True)
    password: str = fields.StringField(required=True, validate=[validate.Length(max=512)], null=False, marshmallow_required=True)
    phone: int = fields.StringField(required=True, validate=[validate.Length(max=11)], null=True, unique=True)
    created_at: dt.datetime = fields.DateTimeField(null=False, load_default=lambda: dt.datetime.utcnow())
    last_login_at: dt.datetime = fields.DateTimeField(null=True)
    current_login_at: dt.datetime = fields.DateTimeField(null=True)
    confirmed_at: dt.datetime = fields.DateTimeField(null=True)
    last_login_ip: str = fields.StringField(validate=[validate.Length(max=60)], null=True)
    current_login_ip: str = fields.StringField(validate=[validate.Length(max=60)], null=True)
    disabled: bool = fields.BooleanField(load_default=False)
    verified: bool = fields.BooleanField(load_default=False)
    roles = fields.ListField(fields.ReferenceField('Role'))

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
                logger.critical(f"Lookup user identified by {email}")
            elif username:
                account = await Account.filter(username=username, deleted=False).get()
                logger.critical(f"Lookup user identified by {username}")
            elif phone:
                account = await Account.filter(phone=phone, deleted=False).get()
                logger.critical(f"Lookup user identified by {phone}")
            elif id:
                account = await Account.filter(id=id, deleted=False).get()
                logger.critical(f"Lookup user identified by {id}")
            else:
                raise NotFoundError("Lookup requested by no identifier provided")
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
    active: bool = fields.BooleanField(load_default=True)
    ip: str = fields.StringField(max_length=16)
    bearer: fields.ReferenceField('Account')
    ctx = SimpleNamespace()

    #def __init__(self, **kwargs):
    #    super().__init__(**kwargs)

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
            and dt.datetime.now(dt.timezone.utc) >= self.expiration_date
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
            "id": self.id,
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
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
                await cls.filter(id=decoded_raw["id"]).prefetch_related("bearer").get()
            )
        except NotCreatedError:
            raise NotFoundError("Session could not be found.")
        return decoded_session

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


@instance.register
class TwoStepSession(Document, VerificationSession):
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


@instance.register
class CaptchaSession(Document, VerificationSession):
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


@instance.register
class AuthenticationSession(Document, Session):
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


@instance.register
class Role(Document, BaseMixin):
    """
    Assigned to an account to authorize an action.

    Attributes:
        name (str): Name of the role.
        description (str): Description of the role.
        permissions (str): Permissions of the role. Must be separated via comma and in wildcard format (printer:query, printer:query,delete).
    """

    name: str = fields.StringField(max_length=255, null=False, unique=True)
    description: str = fields.StringField(max_length=255, null=True)
    permissions: str = fields.StringField(max_length=255, null=True)

    def __repr__(self):
        """Represent instance as a unique string."""
        return f'<Role({self.name})>'

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
            logger.critical(f'Doc: {Role}')
            logger.critical(f'Doc.dir: {dir(Role)}')
            logger.critical(f'Doc.fields: {Role._fields}')
            #role = await Role.find_one(name=name, deleted=False)
            role = await Role.find_one(name=name)
            return role
        except NotCreatedError:
            raise NotFoundError("Role with this name does not exist.")


# `ensure_indexes` must be called, once, for each model we have indexes on (including default `unique`)
async def setup_indexes():
    try:
        await Account.ensure_indexes()
    except Exception as e:
        if 'An equivalent index already exists' in e:
            logger.info('Indexes for Account table already setup')
    try:
        await Role.ensure_indexes()
    except Exception as e:
            logger.info('Indexes for Role table already setup')
    try:
        await Session.ensure_indexes()
    except Exception as e:
            logger.info('Indexes for Session table already setup')
    try:
        await VerificationSession.ensure_indexes()
    except Exception as e:
            logger.info('Indexes for VerificationSession table already setup')
    try:
        await TwoStepSession.ensure_indexes()
    except Exception as e:
        logger.info('Indexes for TwoStepSession table already setup')
    try:
        await CaptchaSession.ensure_indexes()
    except Exception as e:
        logger.info('Indexes for CaptchaSesion table already setup')
