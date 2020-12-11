import bcrypt
from tortoise.exceptions import IntegrityError

from amyrose.core.models import Role, Permission, AuthenticationSession, VerificationSession, Account


async def get_authentication_sessions(account):
    """
    Retrieves all authentication sessions associated with an account.

    :return: authentication_sessions
    """
    return await AuthenticationSession.filter(parent_uid=account.uid).all()


async def get_verification_sessions(account):
    """
    Retrieves all authentication sessions associated with an account.

    :return: authentication_sessions
    """
    return await VerificationSession.filter(parent_uid=account.uid).all()


async def create_role(account, role_name):
    """
    Assigns a role to an account.

    :return: role
    """
    return await Role.create(parent_uid=account.uid, name=role_name)


async def get_account(uid):
    """
    Retrieves account information with a uid.

    :return: account
    """
    return await Account.filter(uid=uid).first()


async def create_account(email, phone, username, password, verified=True):
    """
    This method should not be used for regular user registration. The intent is to make it easy for
    developers and administrators to instantly create accounts.

    :return: account
    """
    try:
        return await Account.create(email=email, username=username, verified=verified, phone=phone,
                                    password=bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt()))
    except IntegrityError:
        raise Account.AccountExistsError()


async def delete_account(uid):
    """
    Renders an account inoperable while remaining on the database.

    :return: account
    """
    account = await Account.filter(uid=uid).first()
    account.deleted = True
    await account.save(update_fields=['deleted'])
    return account


async def get_roles(account):
    """
    Retrieves all roles associated to an account.

    :return: roles
    """
    return await Role.filter(parent_uid=account.uid).all()


async def delete_role(account, uid):
    """
    Renders an role inoperable while remaining on the database.

    :return: role
    """
    role = await Role.filter(parent_uid=account.uid, uid=uid).first()
    role.deleted = True
    await role.save(update_fields=['deleted'])
    return role


async def create_permission(account, permission_name):
    """
    Assigns a permission to an account.
    """
    return await Permission.create(parent_uid=account.uid, name=permission_name)


async def get_permissions(account):
    """
    Retrieves all permissions associated to an account.
    """
    return await Permission.filter(parent_uid=account.uid).all()


async def delete_permission(account, uid):
    """
    Deletes a permission associated to an account.
    """
    permission = await Permission.filter(parent_uid=account.uid, uid=uid).first()
    permission.deleted = True
    await permission.save(update_fields=['deleted'])
    return permission
