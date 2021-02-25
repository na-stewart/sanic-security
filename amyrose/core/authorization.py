import functools
from fnmatch import fnmatch

from amyrose.core.authentication import authenticate
from amyrose.core.models import Role, Permission, Account


async def check_role(account: Account, required_role: str):
    """
    Checks if the account has the required role being requested.

    :param account: Account being checked.

    :param required_role: The role that is required for validation.

    :raises InsufficientRoleError:
    """
    if not await Role.filter(parent_uid=account.uid, name=required_role).exists():
        raise Role.InsufficientRoleError()


async def check_permission(account: Account, required_permission: str):
    """
    Checks if the account has the required permission requested.

    :param account: Account being checked.

    :param required_permission: The permission that is required for validation.

    :raises InsufficientPermissionError:
    """
    permissions = await Permission.filter(parent_uid=account.uid).all()
    for permission in permissions:
        if fnmatch(permission.wildcard, required_permission):
            break
    else:
        raise Permission.InsufficientPermissionError()


def requires_permission(required_permission: str):
    """
    Has the same function as the check_permission method, but is in the form of a decorator and validates client
    permission.

    :param required_permission: The permission that is required for validation.

    :raises InsufficientPermissionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_permission(account, required_permission)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


def requires_role(required_role: str):
    """
    Has the same function as the check_role method, but is in the form of a decorator and validates client role.

    :param required_role: The role that is required for validation.

    :raises InsufficientRoleError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_role(account, required_role)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper
