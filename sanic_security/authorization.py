import functools

from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import DoesNotExist

from sanic_security.authentication import authenticate
from sanic_security.exceptions import AuthorizationError, AnonymousError
from sanic_security.models import Role, Account, AuthenticationSession
from sanic_security.utils import get_ip

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
        logger.warning(
            f"Client {get_ip(request)} attempted an unauthorized action anonymously."
        )
        raise AnonymousError
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        for role_permission, required_permission in zip(
            role.permissions, required_permissions
        ):
            if check_wildcard(required_permission, role_permission):
                request.ctx.session = authentication_session
                return authentication_session
    logger.warning(
        f"Client {get_ip(request)} with account {authentication_session.bearer.id} attempted an unauthorized action."
    )
    raise AuthorizationError("Insufficient permissions required for this action.")


def check_wildcard(input_string: str, pattern: str):
    """
    Evaluates if the input matches the pattern considering wildcards (`*`) and comma-separated options in the `pattern`.

    Args:
        input_string (str): A wildcard string (e.g., "a:b:c").
        pattern (str): A wildcard pattern optional (`*`) or comma-separated values to match against (e.g., "a:b,c:*").

    Returns:
        is_match
    """
    input_parts = input_string.split(":")
    pattern_parts = pattern.split(":")
    input_len = len(input_parts)

    for i, pattern_part in enumerate(pattern_parts):
        if i >= input_len:
            if "*" not in pattern_part:
                return False
            continue
        pattern_subparts = set(pattern_part.split(","))
        if "*" not in pattern_subparts and input_parts[i] not in pattern_subparts:
            return False

    if input_len > len(pattern_parts):
        if "*" not in set(pattern_parts[-1].split(",")):
            return False

    return True


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
        logger.warning(
            f"Client {get_ip(request)} attempted an unauthorized action anonymously."
        )
        raise AnonymousError
    if set(required_roles) & {
        role.name
        for role in await authentication_session.bearer.roles.filter(
            deleted=False
        ).all()
    }:
        request.ctx.session = authentication_session
        return authentication_session
    logger.warning(
        f"Client {get_ip(request)} with account {authentication_session.bearer.id} attempted an unauthorized action"
    )
    raise AuthorizationError("Insufficient roles required for this action")


async def assign_role(
    name: str,
    account: Account,
    description: str = None,
    *permissions: str,
) -> Role:
    """
    Easy account role assignment. Role being assigned to an account will be created if it doesn't exist.

    Args:
        name (str):  The name of the role associated with the account.
        account (Account): The account associated with the created role.
        description (str):  The description of the role associated with the account.
        *permissions (Tuple[str, ...]): The permissions of the role associated with the account. Permissions must in wildcard format.
    """
    try:
        role = await Role.filter(name=name).get()
    except DoesNotExist:
        role = await Role.create(
            name=name,
            description=description,
            permissions=permissions,
        )
    await account.roles.add(role)
    return role


def requires_permission(*required_permissions: str):
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
            await check_permissions(request, *required_permissions)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


def requires_role(*required_roles: str):
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
            await check_roles(request, *required_roles)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator
