import functools
from fnmatch import fnmatch

from sanic.request import Request

from sanic_security.core.authentication import authenticate
from sanic_security.core.exceptions import (
    InsufficientPermissionError,
    InsufficientRoleError,
)
from sanic_security.core.models import Role, Permission


async def check_permissions(request: Request, *required_permissions: str):
    """
    Used to determine if the client has sufficient permissions for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_permissions (Tuple):  The permissions required to authorize an action.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    authentication_session = await authenticate(request)
    client_permissions = await Permission.filter(
        account=authentication_session.account
    ).all()
    for required_permission in required_permissions:
        for client_permission in client_permissions:
            if fnmatch(required_permission, client_permission.wildcard):
                break
        else:
            raise InsufficientPermissionError()
    return authentication_session


async def check_roles(request: Request, *required_roles: str):
    """
    Used to determine if the client has sufficient roles for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_roles (Tuple):  The roles required to authorize an action.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    authentication_session = await authenticate(request)
    for role in required_roles:
        if await Role.filter(
            account=authentication_session.account, name=role
        ).exists():
            break
    else:
        raise InsufficientRoleError()
    return authentication_session


def require_permissions(*required_permissions: str):
    """
    Used to determine if the client has sufficient permissions for an action.

    Args:
        *required_permissions (Tuple[str, ...]):  The permissions required to authorize an action.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/authorize')
            @require_permissions('admin:update', 'admin:create')
            async def on_authorize(request, authentication_session):
                return text('User is authorized to update and create data!')

    Raises:
        AccountError
        SessionError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await check_permissions(
                request, *required_permissions
            )
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper


def require_roles(*required_roles: str):
    """
    Used to determine if the client has sufficient roles for an action.

    Args:
        *required_roles (Tuple[str, ...]):  The roles required to authorize an action.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/authorize')
            @require_roles('Admin', 'Moderator')
            async def on_authorize(request, authentication_session):
                return text('User is authorized with the role Admin or Moderator!')

    Raises:
        AccountError
        SessionError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await check_roles(request, *required_roles)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper
