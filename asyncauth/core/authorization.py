import functools
from fnmatch import fnmatch

from asyncauth.core.authentication import authenticate
from asyncauth.core.models import Role, Permission, Account


async def check_roles(account: Account, *required_roles: str):
    """
    Checks if the account has the required roles being requested.

    :param account: Account being checked.

    :param required_roles: The roles required to authorize an action.

    :raises InsufficientRoleError:
    """
    for role in required_roles:
        if await Role.filter(account=account, name=role).exists():
            break
    else:
        raise Role.InsufficientRoleError()


async def check_permissions(account: Account, *required_permissions: str):
    """
    Checks if the account has the required permissions requested.

    :param account: Account being checked.

    :param required_permissions: The permissions required to authorize an action.

    :raises InsufficientPermissionError:
    """
    for required_permission in required_permissions:
        permission = await Permission.filter(account=account, wildcard=required_permission).first()
        if permission is not None and fnmatch(required_permission, permission.wildcard):
            break
    else:
        raise Permission.InsufficientPermissionError()


def require_permissions(*required_permissions: str):
    """
    Has the same function as the check_permissions method, but is in the form of a decorator and validates client
    permission.

    :param required_permissions: The permissions required to authorize an action.

    :raises InsufficientPermissionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await authenticate(request)
            await check_permissions(authentication_session.account, *required_permissions)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


def require_roles(*required_roles: str):
    """
    Has the same function as the check_roles method, but is in the form of a decorator and validates client role.

    :param required_roles: The roles required to authorize an action.

    :raises InsufficientRoleError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await authenticate(request)
            await check_roles(authentication_session.account, *required_roles)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper
