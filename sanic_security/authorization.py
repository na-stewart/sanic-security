import functools
import logging
from fnmatch import fnmatch

from sanic.request import Request
from tortoise.exceptions import DoesNotExist

from sanic_security.authentication import authenticate
from sanic_security.exceptions import AuthorizationError
from sanic_security.models import Role, Account, AuthenticationSession
from sanic_security.utils import get_ip


async def check_permissions(
    request: Request, *required_permissions: str
) -> AuthenticationSession:
    """
    Authenticates client and determines if the account has sufficient permissions for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_permissions (Tuple[str, ...]):  The permissions required to authorize an action.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
        AuthorizationError
    """
    authentication_session = await authenticate(request)
    async for account_role in authentication_session.bearer.roles:
        for required_permission in required_permissions:
            for permission in account_role.permissions.split(","):
                if fnmatch(required_permission, permission):
                    break
            else:
                logging.warning(
                    f"Client ({authentication_session.bearer.email}/{get_ip(request)}) has insufficient permissions."
                )
                raise AuthorizationError(
                    "Insufficient permissions required for this action."
                )
    return authentication_session


async def check_roles(request: Request, *required_roles: str) -> AuthenticationSession:
    """
    Authenticates client and determines if the account has sufficient roles for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_roles (Tuple[str, ...]):  The roles required to authorize an action.

    Returns:
        authentication_session

    Raises:
        AccountError
        SessionError
        AuthorizationError
    """
    authentication_session = await authenticate(request)
    async for account_role in authentication_session.bearer.roles:
        if account_role.name in required_roles:
            break
    else:
        logging.warning(
            f"Client ({authentication_session.bearer.email}/{get_ip(request)}) has insufficient roles."
        )
        raise AuthorizationError("Insufficient roles required for this action.")
    return authentication_session


def require_permissions(*required_permissions: str):
    """
    Authenticates client and determines if the account has sufficient permissions for an action.

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
        AuthorizationError
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
    Authenticates client and determines if the account has sufficient roles for an action.

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
        AuthorizationError
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            authentication_session = await check_roles(request, *required_roles)
            return await func(request, authentication_session, *args, **kwargs)

        return wrapped

    return wrapper


async def assign_role(
    name: str, description: str, permissions: str, account: Account
) -> Role:
    """
    Quick creation of a role associated with an account.

    Args:
        name (str):  The name of the role associated with the account.
        description (str):  The description of the role associated with the account.
        permissions (str):  The permissions of the role associated with the account. Must be separated via comma and in wildcard format.
        account (Account): the account associated with the created role.
    """
    try:
        role = await Role.filter(name=name, permissions=permissions).get()
    except DoesNotExist:
        role = await Role.create(
            description=description, permissions=permissions, name=name
        )
    await account.roles.add(role)
    return role
