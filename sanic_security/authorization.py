import functools
from fnmatch import fnmatch

from sanic.request import Request

from sanic_security.authentication import authenticate
from sanic_security.exceptions import (
    InsufficientPermissionError,
    InsufficientRoleError,
)
from sanic_security.models import Role, Permission, Account


async def check_permissions(request: Request, *required_permissions: str):
    """
    Used to determine if the client has sufficient permissions for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_permissions (Tuple[str, ...]):  The permissions required to authorize an action.

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
        *required_roles (Tuple[str, ...]):  The roles required to authorize an action.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
    """
    authentication_session = await authenticate(request)
    client_roles = await Role.filter(account=authentication_session.account).all()
    for role in client_roles:
        if role in client_roles:
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

            @app.post("api/auth/perms")
            @require_permissions("admin:update", "employee:add")
            async def on_require_perms(request, authentication_session):
                return text("Account permitted.")

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
        *required_roles (Tuple[str, ...]): The roles required to authorize an action.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/auth/roles")
            @require_roles("Admin", "Moderator")
            async def on_require_roles(request, authentication_session):
                return text("Account permitted")

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


async def create_role(name: str, account: Account):
    """
    Quick creation of a role associated with an account.

    Args:
        name (str):  The name of the role associated with the account.
        account (Account): the account associated with the created role.
    """
    return await Role().create(account=account, name=name)


async def create_permission(wildcard: str, account: Account):
    """
    Quick creation of a permission associated with an account.

    Args:
        wildcard (str):  The wildcard of the permission associated with the account.
        account (Account): the account associated with the created permission.
    """
    return await Permission.create(account=account, wildcard=wildcard)
