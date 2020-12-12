import bcrypt
from sanic.request import Request
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Role, Permission, AuthenticationSession, VerificationSession, Account


async def get_authentication_sessions(account: Account):
    """
    Retrieves all authentication sessions associated with an account.

    :param account: Account associated with sessions.

    :return: authentication_sessions
    """
    return await AuthenticationSession.filter(parent_uid=account.uid).all()


async def invalidate_authentication_session(authentication_session: AuthenticationSession):
    """
    Renders an authentication invalidated.

    :param authentication_session: Session to be invalidated.

    :return: authentication_sessions
    """
    authentication_session.valid = False
    await authentication_session.save(update_fields=['valid'])
    return authentication_session


async def get_verification_sessions(account: Account):
    """
    Retrieves all authentication sessions associated with an account.

    :param account: Account associated with sessions.

    :return: verification_sessions
    """
    return await VerificationSession.filter(parent_uid=account.uid).all()


async def invalidate_verification_session(verification_session: VerificationSession):
    """
    Renders a verification session invalid.

    :param verification_session: Session to be invalidated.

    :return: authentication_sessions
    """
    verification_session = await VerificationSession.filter(uid=verification_session.uid).first()
    verification_session.valid = False
    await verification_session.save(update_fields=['valid'])
    return verification_session


async def create_role(account: Account, role: str):
    """
    Assigns a role to an account.

    :param account: Account to be assigned role.

    :param role: Role to be created and assigned to account.

    :return: role
    """
    return await Role.create(parent_uid=account.uid, name=account)


async def get_client(request: Request):
    """
    Retrieves account information from an authentication session found within cookie.

    :param request: Sanic request parameter.

    :return: account
    """
    decoded_cookie = AuthenticationSession.from_cookie(request.cookies.get('authtkn'))
    account = await Account.filter(uid=decoded_cookie['parent_uid']).first()
    return account


async def create_account(email: str, username: str, password: str, phone: str = None, verified: bool = False):
    """
    This method should not be used for regular user registration. The intent is to make it easy for
    developers and administrators to instantly create accounts.

    :param email: Email of account.

    :param username: Username of account.

    :param password: Password of account.

    :param phone: Phone of account

    :param verified: Verification status of account.

    :return: account
    """
    try:
        return await Account.create(email=email, username=username, verified=verified, phone=phone,
                                    password=bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt()))
    except IntegrityError:
        raise Account.AccountExistsError()


async def delete_account(account: Account):
    """
    Renders an account inoperable while remaining on the database.

    :param account: Account to be deleted.

    :return: account
    """
    account = await Account.filter(uid=account.uid).first()
    account.deleted = True
    await account.save(update_fields=['deleted'])
    return account


async def get_roles(account: Account):
    """
    Retrieves all roles associated to an account.

    :param account: Account associated to roles.

    :return: roles
    """
    return await Role.filter(parent_uid=account.uid).all()


async def delete_role(role: Role):
    """
    Renders an role inoperable while remaining on the database.

    :param role: Role to be deleted.

    :return: role
    """
    role = await Role.filter(uid=role.uid).first()
    role.deleted = True
    await role.save(update_fields=['deleted'])
    return role


async def create_permission(account: Account, permission: str):
    """
    Assigns a permission to an account.

    :param account: Account to be associated to a role.

    :param permission: Permission to be associated to an account.

    :return: permission
    """
    return await Permission.create(parent_uid=account.uid, name=permission)


async def get_permissions(account: Account):
    """
    Retrieves all permissions associated to an account.

    :param account: Account associated with permissions.

    :return: permissions
    """
    return await Permission.filter(parent_uid=account.uid).all()


async def delete_permission(permission: Permission):
    """
    Renders a permission while remaining on the database.

    :param permission: Permission to be deleted.

    :return: permission
    """
    permission = await Permission.filter(uid=permission.uid).first()
    permission.deleted = True
    await permission.save(update_fields=['deleted'])
    return permission
