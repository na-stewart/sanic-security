import functools
from fnmatch import fnmatch

from amyrose.core.authentication import authenticate
from amyrose.core.models import Role, Permission
from amyrose.core.utils import url_endpoint

endpoints_requiring_role = {}
endpoints_requiring_permission = {}


async def check_role(account, authorized_role):
    if not await Role.filter(parent_uid=account.uid, name=authorized_role).exists():
        raise Role.InsufficientRoleError()


async def check_permissions(account, authorized_permission):
    permissions = await Permission.filter(parent_uid=account.uid).all()
    for permission in permissions:
        if fnmatch(permission.name, authorized_permission):
            break
    else:
        raise Permission.InsufficientPermissionError()


async def create_role(account, role):
    await Role().create(parent_uid=account.uid, name=role)


async def create_permission(account, perm):
    await Permission().create(parent_uid=account.uid, name=perm)


async def authorize(request, account):
    endpoint = url_endpoint(request.url)
    endpoint_role = endpoints_requiring_role.get(endpoint)
    endpoint_permission = endpoints_requiring_permission.get(endpoint)
    if endpoint_role:
        await check_role(account, endpoint_role)
    if endpoint_permission:
        await check_permissions(account, endpoint_permission)


def requires_permission(permission):
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_permissions(account, permission)
            return await func(request, *args, **kwargs)
        return wrapped
    return wrapper


def requires_role(role):
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            account, authentication_session = await authenticate(request)
            await check_role(account, role)
            return await func(request, *args, **kwargs)
        return wrapped
    return wrapper

