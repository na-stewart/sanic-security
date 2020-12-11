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
