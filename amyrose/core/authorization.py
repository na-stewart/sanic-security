from fnmatch import fnmatch

from amyrose.core.authentication import append_endpoints_requiring_authentication
from amyrose.core.models import Role, Permission
from amyrose.core.utils import url_endpoint

endpoints_requiring_role = {}
endpoints_requiring_permission = {}


async def _check_role(account, authorized_role):
    if not await Role.filter(parent_uid=account.uid, name=authorized_role).exists():
        raise Role.InsufficientRoleError()


async def _check_permissions(account, authorized_permission):
    permissions = await Permission.filter(parent_uid=account.uid).all()
    for permission in permissions:
        if fnmatch(permission.name, authorized_permission):
            break
    else:
        raise Permission.InsufficientPermissionsError()


async def create_role(account, role):
    await Role().create(parent_uid=account.uid, name=role)


async def create_permission(account, perm):
    await Permission().create(parent_uid=account.uid, name=perm)


async def authorize(request, account):
    endpoint = url_endpoint(request.url)
    endpoint_role = endpoints_requiring_role.get(endpoint)
    endpoint_permission = endpoints_requiring_permission.get(endpoint)
    if endpoint_role:
        await _check_role(account, endpoint_role)
    if endpoint_permission:
        await _check_permissions(account, endpoint_permission)


def requires_permission(*args, **kwargs):
    def inner(func):
        append_endpoints_requiring_authentication(args[0])
        endpoints_requiring_permission[args[0]] = args[1]
        return func

    return inner


def requires_role(*args, **kwargs):
    def inner(func):
        append_endpoints_requiring_authentication(args[0])
        endpoints_requiring_role[args[0]] = args[1]
        return func

    return inner
