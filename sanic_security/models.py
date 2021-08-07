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
from sanic.request import Request
from sanic.response import HTTPResponse, file
from tortoise import fields, Model

from sanic_security.exceptions import *
from sanic_security.utils import get_ip, security_cache_path, dir_exists, config
from sanic_security.lib.smtp import send_email
from sanic_security.lib.twilio import send_sms


class BaseModel(Model):
    """
    Base Sanic Security model that all other models derive from.

    Attributes:
        id (int): Primary key of model.
        uid (bytes): Recommended identifier to be used for filtering or retrieval.
        account (Account): Parent account associated with this model.
        date_created (datetime): Time this model was created in the database.
        date_updated (datetime): Time this model was updated in the database.
        deleted (bool): This attribute allows you to mark a model as deleted and filter it from queries without removing it from the database.
    """

    id = fields.IntField(pk=True)
    uid = fields.UUIDField(unique=True, default=uuid.uuid1, max_length=36)
    account = fields.ForeignKeyField("models.Account", null=True)
    date_created = fields.DatetimeField(auto_now_add=True)
    date_updated = fields.DatetimeField(auto_now=True)
    deleted = fields.BooleanField(default=False)

    def json(self):
        """
        A JSON serializable dict to be used in a HTTP request or response.

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


class Account(BaseModel):
    """
    Contains all identifiable user information.

    Attributes:
        username (str): Public identifier.
        email (str): Private identifier and can be used for verification.
        phone (str): Mobile phone number with country code included and can be used for verification. May be null or empty.
        password (bytes): Password of account for protection. Must be set using the hash_password method found in the utils module.
        disabled (bool): Renders the account unusable but available.
        verified (bool): Determines if the account needs verification before use.
    """

    username = fields.CharField(max_length=45)
    email = fields.CharField(unique=True, max_length=45)
    phone = fields.CharField(unique=True, max_length=14, null=True)
    password = fields.BinaryField()
    disabled = fields.BooleanField(default=False)
    verified = fields.BooleanField(default=False)

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

    @staticmethod
    async def get_via_email(email: str):
        """
        Retrieve an account with an email.

        Args:
            email (str): Email associated to account being retrieved.

        Returns:
            account
        """
        account = await Account.filter(email=email).first()
        return account


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

    def encode(self, response: HTTPResponse, secure: bool = True, tag: str = "sec"):
        """
        Transforms session into jwt and then is stored in a cookie.

        Args:
            response (HTTPResponse): Sanic response object used to store JWT into a cookie on the client.
            secure (bool): Determines if connections must be SSL encrypted (aka https) for cookie to be used.
            tag (str): Identifier applied to encoded session cookie.
        """
        payload = {
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
            "uid": str(self.uid),
            "ip": self.ip,
        }
        cookie = f"{tag}_{self.__class__.__name__}"
        encoded = jwt.encode(payload, config["SECURITY"]["secret"], "HS256")
        response.cookies[cookie] = encoded
        response.cookies[cookie]["secure"] = secure
        response.cookies[cookie]["httponly"] = True

    @classmethod
    def decode_raw(cls, request: Request, tag: str = "sec"):
        """
        Decodes JWT token from client cookie into a python dict.

        Args:
            request (Request): Sanic request parameter.
            tag (str): Identifier found applied to encoded session cookie.

        Returns:
            session_dict
        """
        cookie = request.cookies.get(f"{tag}_{cls.__name__}")
        try:
            if not cookie:
                raise DecodingError(f"No session provided by client.")
            else:
                return jwt.decode(cookie, config["SECURITY"]["secret"], "HS256")
        except DecodeError as e:
            raise DecodingError(e)

    @classmethod
    async def decode(cls, request: Request, tag: str = "sec"):
        """
        Decodes JWT token from client cookie to a Sanic Security session.

        Args:
            request (Request): Sanic request parameter.
            tag (str): Identifier found applied to encoded session cookie.

        Returns:
            session

        Raises:
            DecodeError
        """
        decoded = cls.decode_raw(request, tag)
        decoded_session = (
            await cls.filter(uid=decoded.get("uid")).prefetch_related("account").first()
        )
        return decoded_session

    async def crosscheck_location(self, request):
        """
        Checks if client using session is in a known location (ip address). Prevents cookie jacking.

        Raises:
            UnknownLocationError:
        """

        if not await self.filter(ip=get_ip(request), account=self.account).exists():
            raise CrosscheckError(
                "Client location does not match any existing session location."
            )

    class Meta:
        abstract = True


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
    async def initialize_cache():
        """
        Creates verification session cache and generates required files.

        Args:
            app (Sanic): Sanic Framework app.
        """
        raise NotImplementedError()

    @classmethod
    async def get_random_code(cls):
        """
        Retrieves a random cached verification session code.
        """
        raise NotImplementedError()

    async def crosscheck_code(self, code: str):
        """
        Used to check if code passed is equivalent to the verification session code.

        Args:
            code (str): Code being cross-checked with verification session code.

        Raises:
            CrossCheckError
            MaximumAttemptsError
        """
        if self.attempts >= 5:
            raise MaximumAttemptsError()
        elif self.code != code:
            self.attempts += 1
            await self.save(update_fields=["attempts"])
            raise CrosscheckError("The value provided does not match.")
        else:
            self.valid = False
            await self.save(update_fields=["valid"])

    class Meta:
        abstract = True


class TwoStepSession(VerificationSession):
    """
    Validates a client using a code sent via email or text.
    """

    @staticmethod
    async def initialize_cache():
        if not dir_exists(f"{security_cache_path}/verification"):
            async with aiofiles.open(
                f"{security_cache_path}/verification/codes.txt", mode="w"
            ) as f:
                for i in range(100):
                    code = "".join(
                        random.choices(string.ascii_letters + string.digits, k=10)
                    )
                    await f.write(code + " ")

    @classmethod
    async def get_random_code(cls):
        await cls.initialize_cache()
        async with aiofiles.open(
            f"{security_cache_path}/verification/codes.txt", mode="r"
        ) as f:
            codes = await f.read()
            return random.choice(codes.split())

    async def text_code(self, code_prefix="Your code is: "):
        """
        Sends account associated with this session the code via text.

        Args:
            code_prefix (str): Message being sent with code, for example "Your code is: ".
        """
        await send_sms(self.account.phone, code_prefix + self.code)

    async def email_code(
        self, subject="Verification", code_prefix="Your code is:\n\n "
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
    Validates a client as human with a captcha challenge.
    """

    @staticmethod
    async def initialize_cache():
        if not dir_exists(f"{security_cache_path}/captcha"):
            loop = asyncio.get_running_loop()
            image = ImageCaptcha(190, 90, fonts=[config["SECURITY"]["captcha_font"]])
            for i in range(100):
                code = "".join(
                    random.choices("123456789qQeErRtTyYiIaAdDfFgGhHlLbBnN", k=6)
                )
                await loop.run_in_executor(
                    None,
                    image.write,
                    code,
                    f"{security_cache_path}/captcha/{code}.png",
                )

    @classmethod
    async def get_random_code(cls):
        await cls.initialize_cache()
        return random.choice(os.listdir(f"{security_cache_path}/captcha")).split(".")[0]

    async def get_image(self):
        """
        Retrieves captcha image file.

        Returns:
            captcha_image
        """
        return await file(f"{security_cache_path}/captcha/{self.code}.png")


class AuthenticationSession(Session):
    """
    Used to authenticate a client and provide access to a user's account.

    Attributes:
        two_factor (bool): Determines if authentication session requires a second factor to be used for authentication.
    """

    two_factor = fields.BooleanField(default=False)


class SessionFactory:
    """
    Prevents human error when creating sessions.
    """

    async def get(
        self, session_type: str, request: Request, account: Account = None, **kwargs
    ):
        """
         Creates and returns a session with all of the fulfilled requirements.

        Args:
            session_type (str): The type of session being retrieved. Available types are: captcha, twostep, and authentication.
            request (Request):  Sanic request paramater.
            account (Account): Account being associated to the session.
            kwargs: Extra arguments applied to session creation.

        Returns:
            session

        Raises:
            ValueError
        """
        if session_type == "captcha":
            return await CaptchaSession.create(
                **kwargs,
                ip=get_ip(request),
                code=await CaptchaSession.get_random_code(),
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(minutes=1),
            )
        elif session_type == "twostep":
            return await TwoStepSession.create(
                **kwargs,
                code=await TwoStepSession.get_random_code(),
                ip=get_ip(request),
                account=account,
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(minutes=5),
            )
        elif session_type == "authentication":
            return await AuthenticationSession.create(
                **kwargs,
                account=account,
                ip=get_ip(request),
                expiration_date=datetime.datetime.utcnow()
                + datetime.timedelta(days=30),
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
