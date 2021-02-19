import functools
from fnmatch import fnmatch
from amyrose.core.authentication import authenticate
from amyrose.core.dto import RoleDTO, PermissionDTO
from amyrose.core.models import Role, Permission, Account

role_dto = RoleDTO()
permission_dto = PermissionDTO()


async def check_role(account: Account, required_role: str):
    """
    Checks if the account has the required role being requested.

    :param account: Account being checked.

    :param required_role: The role that is required for validation.

    :raises InsufficientRoleError:
    """
    if not await role_dto.has_role(account.uid, required_role):
        raise Role.InsufficientRoleError()


async def check_permission(account: Account, required_permission: str):
    """
    Checks if the account has the required permission requested.

    :param account: Account being checked.

    :param required_permission: The permission that is required for validation.

    :raises InsufficientPermissionError:
    """
    permissions = await permission_dto.get_permissions(account.uid)
    for permission in permissions:
        if fnmatch(permission.name, required_permission):
            break
    else:
        raise Permission.InsufficientPermissionError()


def requires_permission(required_permission: str):
    """
    Has the same function as the check_permission method, but is in the form of a decorator and validates client.

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
    Has the same function as the check_role method, but is in the form of a decorator and validates client.

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
