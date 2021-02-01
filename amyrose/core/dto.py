from typing import TypeVar, Generic, Type

import bcrypt
from sanic.request import Request
from amyrose.core.models import Account, VerificationSession, AuthenticationSession, Role, Permission, Session, \
    CaptchaSession

T = TypeVar('T')


class DTO(Generic[T]):

    def __init__(self, t: Type[T]):
        self.t = t

    async def get_all(self):
        """
        Returns a list of models.

        :return: List[T]
        """
        return await self.t().filter(deleted=False).all()

    async def get(self, uid: str):
        """
        Retrieves a model via uid.

        :param uid: Uid of model.

        :return: T
        """
        return await self.t().filter(uid=uid, deleted=False).first()

    async def get_by_parent(self, parent_uid: str):
        """
        Retrieves a model via parent uid.

        :param parent_uid: Parent uid of model.

        :return: T
        """
        return await self.t().filter(parent_uid=parent_uid, deleted=False).first()

    async def create(self, **kwargs):
        """
        Initializes a model and creates in database.

        :param kwargs: Model parameters.

        :return: T
        """
        for key, value in kwargs.items():
            if value is not None:
                if not isinstance(value, bool) and not value:
                    raise self.t.EmptyEntryError(key.title() + ' is empty!')

        return await self.t().create(**kwargs)

    async def update(self, t: T, fields: list):
        """
        Updates a model in the database.

        :param t: Model being updated in database.

        :param fields: Fields being updated in the model to be updated in database.

        :return: T
        """
        await t.save(update_fields=fields)
        return t

    async def delete(self, t: T):
        """
        Renders a model inoperable while remaining in the database.

        :param t: Model being deleted.

        :return: T
        """
        t.deleted = True
        return self.update(t, ['deleted'])


class CaptchaSessionDTO(DTO):
    def __init__(self):
        super().__init__(CaptchaSession)

    async def get_client_img(self, request):
        """
        Retrieves image path of client captcha.

        :return: captcha_img_path
        """
        captcha_session = await CaptchaSession().decode(request)
        return './resources/captcha/img/' + captcha_session.captcha + '.png'


class AccountDTO(DTO):
    def __init__(self):
        super().__init__(Account)

    async def disable(self, account: Account):
        """
        Renders an account inoperable while remaining retrievable.

        :param account: account  being disabled

        :return: account
        """
        account.disabled = True
        return self.update(account, ['disabled'])

    async def enable(self, account: Account):
        """
        Enabled an account after being disabled.

        :param account: account being enabled

        :return: account
        """
        account.enable = True
        return self.update(account, ['disabled'])

    async def get_by_email(self, email: str):
        """
        Retrieves account via email.

        :param email: Email of account being retrieved.

        :return: T
        """
        return await self.t().filter(email=email).first()

    async def get_client(self, request: Request):
        """
        Retrieves account information from an authentication session found within cookie.
        :param request: Sanic request parameter.
        :return: account
        """
        authentication_session = await AuthenticationSession().decode(request, raw=True)
        account = await self.get(authentication_session.get('parent_uid'))
        return account

    def hash_password(self, password):
        """
        Turns passed text into hashed password
        :param password: Password to be hashed.
        :return: hashed
        """
        if password:
            return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        else:
            raise self.t.EmptyEntryError('password is empty!')



class VerificationSessionDTO(DTO):
    def __init__(self):
        super().__init__(VerificationSession)


class AuthenticationSessionDTO(DTO):
    def __init__(self):
        super().__init__(AuthenticationSession)

    async def validate_access_location(self, request: Request):
        """
        Validates if client using session is in a known location. Prevents cookie jacking.

        :param request: Sanic request parameter.

        :param decoded_cookie: Decoded cookie from client.

        :raises UnknownLocationError:
        """
        decoded_authentication_session = AuthenticationSession().decode(request, True)
        if not await AuthenticationSession.filter(ip=request.ip,
                                                  parent_uid=decoded_authentication_session['parent_uid']).exists():
            raise Session.UnknownLocationError()


class RoleDTO(DTO):
    def __init__(self):
        super().__init__(Role)

    async def has_role(self, account: Account, role: str):
        """
        Checks if the account has the required role being requested.

        :param account: Account being checked.

        :param role: The role that is required for validation.

        :return: has_role
        """
        return await self.t().filter(parent_uid=account.uid, name=role).exists()

    async def assign_role(self, account: Account, role: str):
        """
        Creates a role associated with an account

        :param account: Account associated with role.

        :param role: role to be associated with account.

        :return: role
        """

        return await self.create(parent_uid=account.uid, name=role)


class PermissionDTO(DTO):

    def __init__(self):
        super().__init__(Permission)

    async def assign_permission(self, account: Account, permission: str):
        """
        Creates a permission associated with an account

        :param account: Account associated with role.

        :param permission: permission to be associated with account.

        :return: permission
        """

        return await self.create(parent_uid=account.uid, name=permission)

    async def get_permissions(self, account: Account):
        """
        Retrieves all permissions associated with an account.

        :param account: Account associated with permissions

        :return: permissions
        """
        return await self.t().filter(parent_uid=account.uid).all()
