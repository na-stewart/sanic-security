import functools
import logging
from fnmatch import fnmatch

from sanic.request import Request
from tortoise.exceptions import DoesNotExist

from sanic_security.authentication import authenticate
from sanic_security.exceptions import AuthorizationError
from sanic_security.models import Role, Account, AuthenticationSession
from sanic_security.utils import get_ip


"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2021 Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


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
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        AuthorizationError
    """
    authentication_session = await authenticate(request)
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        for required_permission, role_permission in zip(
            required_permissions, role.permissions.split(", ")
        ):
            if fnmatch(required_permission, role_permission):
                return authentication_session
    logging.warning(
        f"Client ({authentication_session.bearer.email}/{get_ip(request)}) has insufficient permissions."
    )
    raise AuthorizationError("Insufficient permissions required for this action.")


async def check_roles(request: Request, *required_roles: str) -> AuthenticationSession:
    """
    Authenticates client and determines if the account has sufficient roles for an action.

    Args:
        request (Request): Sanic request parameter.
        *required_roles (Tuple[str, ...]):  The roles required to authorize an action.

    Returns:
        authentication_session

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        AuthorizationError
    """
    authentication_session = await authenticate(request)
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        if role.name in required_roles:
            return authentication_session
    logging.warning(
        f"Client ({authentication_session.bearer.email}/{get_ip(request)}) has insufficient roles."
    )
    raise AuthorizationError("Insufficient roles required for this action.")


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
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
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
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
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
        permissions (str):  The permissions of the role associated with the account. Permissions must be separated via comma and in wildcard format.
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
