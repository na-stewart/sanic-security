import functools
from fnmatch import fnmatch
from amyrose.core.authentication import authenticate
from amyrose.core.models import Role, Permission


async def check_role(account, required_role_name):
    """
    Verifies if the passed account has the required role.
    """
    if not await Role.filter(parent_uid=account.uid, name=required_role_name).exists():
        raise Role.InsufficientRoleError()


async def check_permissions(account, required_permission_name):
    """
    Verifies if the passed account has the required permission.
    """
    permissions = await Permission.filter(parent_uid=account.uid).all()
    for permission in permissions:
        if fnmatch(permission.name, required_permission_name):
            break
    else:
        raise Permission.InsufficientPermissionError()


async def create_role(account, role_name):
    """
    Assigns a role to an account.

    :return: role
    """
    return await Role().create(parent_uid=account.uid, name=role_name)


async def get_roles(account):
    """
    Retrieves all roles associated to an account.

    :return: roles
    """
    return await Role().filter(parent_uid=account.parent_uid).all()


async def delete_role(account, role_name):
    """
    Renders an role inoperable while remaining on the database.

    :return: role
    """
    role = await Role().filter(parent_uid=account, name=role_name).first()
    role.deleted = True
    return role


async def create_permission(account, permission_name):
    """
    Assigns a permission to an account.
    """
    return await Permission().create(parent_uid=account.uid, name=permission_name)


async def get_account_permissions(account):
    """
    Retrieves all permissions associated to an account.
    """
    return await Permission().filter(parent_uid=account.parent_uid).all()


async def delete_account_permission(account, permission_name):
    """
    Deletes a permission associated to an account.
    """
    permission = await Permission.filter(parent_uid=account, name=permission_name).first()
    permission.deleted = True
    await permission.save(update_fields=['deleted'])
    return permission


def requires_permission(permission):
    """
    A decorator used to verify if a client has permission before executing a method.
    """
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_permissions(account, permission)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


def requires_role(role):
    """
    A decorator used to verify if a client has the required role before executing a method.
    """
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_role(account, role)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper
