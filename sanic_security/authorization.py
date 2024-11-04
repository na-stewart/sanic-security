import functools
from fnmatch import fnmatch

from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import DoesNotExist

from sanic_security.authentication import authenticate
from sanic_security.exceptions import AuthorizationError, AnonymousError
from sanic_security.models import Role, Account, AuthenticationSession

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
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
        AnonymousError
    """
    authentication_session = await authenticate(request)
    if authentication_session.anonymous:
        raise AnonymousError()
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        for required_permission, role_permission in zip(
            required_permissions, role.permissions.split(", ")
        ):
            if fnmatch(required_permission, role_permission):
                return authentication_session
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
        AnonymousError
    """
    authentication_session = await authenticate(request)
    if authentication_session.anonymous:
        raise AnonymousError()
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        if role.name in required_roles:
            return authentication_session
    raise AuthorizationError("Insufficient roles required for this action.")


async def assign_role(
    name: str, account: Account, permissions: str = None, description: str = None
) -> Role:
    """
    Easy account role assignment. Role being assigned to an account will be created if it doesn't exist.

    Args:
        name (str):  The name of the role associated with the account.
        account (Account): The account associated with the created role.
        permissions (str):  The permissions of the role associated with the account. Permissions must be separated via comma and in wildcard format.
        description (str):  The description of the role associated with the account.
    """
    try:
        role = await Role.filter(name=name).get()
    except DoesNotExist:
        role = await Role.create(
            description=description, permissions=permissions, name=name
        )
    await account.roles.add(role)
    logger.info(f"Role {role.id} has been assigned to account {account.id}.")
    return role


def require_permissions(*required_permissions: str):
    """
    Authenticates client and determines if the account has sufficient permissions for an action.

    Args:
        *required_permissions (Tuple[str, ...]):  The permissions required to authorize an action.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/auth/perms")
            @require_permissions("admin:update", "employee:add")
            async def on_require_perms(request):
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
        AnonymousError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.authentication_session = await check_permissions(
                request, *required_permissions
            )
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_roles(*required_roles: str):
    """
    Authenticates client and determines if the account has sufficient roles for an action.

    Args:
        *required_roles (Tuple[str, ...]): The roles required to authorize an action.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post("api/auth/roles")
            @require_roles("Admin", "Moderator")
            async def on_require_roles(request):
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
        AnonymousError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.authentication_session = await check_roles(
                request, *required_roles
            )
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator
