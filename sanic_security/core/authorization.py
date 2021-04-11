import functools
from fnmatch import fnmatch

from sanic.request import Request

from sanic_security.core.authentication import authenticate
from sanic_security.core.models import Role, Permission


async def check_permissions(request: Request, *required_permissions: str):
    """
    Checks if the client has the required permissions.

    :param request: Sanic request parameter.

    :param required_permissions: The permissions required to authorize an action.

    :raises InsufficientPermissionError:
    """

    authentication_session = await authenticate(request)
    client_permissions = await Permission.filter(account=authentication_session.account).all()
    for required_permission in required_permissions:
        for client_permission in client_permissions:
            if fnmatch(required_permission, client_permission.wildcard):
                break
        else:
            raise Permission.InsufficientPermissionError()
    return authentication_session


async def check_roles(request: Request, *required_roles: str):
    """
    Checks if the client has the required roles.

    :param request: Sanic request parameter.

    :param required_roles: The roles required to authorize an action.

    :raises InsufficientRoleError:
    """

    authentication_session = await authenticate(request)
    for role in required_roles:
        if await Role.filter(account=authentication_session.account, name=role).exists():
            break
    else:
        raise Role.InsufficientRoleError()
    return authentication_session


def require_permissions(*required_permissions: str):
    """
    Checks if the client has the required permissions.

    :param required_permissions: The permissions required to authorize an action.

    :raises InsufficientPermissionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await check_permissions(request, *required_permissions)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper


def require_roles(*required_roles: str):
    """
    Checks if the client has the required roles.

    :param required_roles: The roles required to authorize an action.

    :raises InsufficientRoleError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await check_roles(request, *required_roles)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper
