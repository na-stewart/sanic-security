from fnmatch import fnmatch

from amyrose.core.authentication import endpoints_requiring_authentication, requires_authentication
from amyrose.core.models import Role, Permission, InsufficientRoleError, \
    InsufficientPermissionsError
from amyrose.core.utils import url_endpoint

endpoints_requiring_role = {}
endpoints_requiring_permission = {}


async def _check_role(authentication_session, authorized_role):
    if not await Role.filter(parent_uid=authentication_session.parent_uid, name=authorized_role).exists():
        raise InsufficientRoleError('You do not have the required role for this action.', 403)


async def _check_permissions(authentication_session, authorized_permission):
    permissions = await Permission.filter(parent_uid=authentication_session.parent_uid).all()
    for permission in permissions:
        if fnmatch(authorized_permission, permission.name):
            break
    else:
        raise InsufficientPermissionsError('You do not have the required permissions for this action.', 403)


async def create_role(account, role):
    await Role(parent_uid=account.uid, name=role).create()


async def create_permission(account, perm):
    await Permission(parent_uid=account.uid, name=perm).create()


async def authorize(request, authentication_session):
    endpoint = url_endpoint(request.url)
    endpoint_role = endpoints_requiring_role.get(endpoint)
    endpoint_permission = endpoints_requiring_permission.get(endpoint)
    if endpoint_role:
        await _check_role(authentication_session, endpoint_role)
    if endpoint_permission:
        await _check_permissions(authentication_session, endpoint_permission)
    return authentication_session


def requires_permission(*args, **kwargs):
    def inner(func):
        requires_authentication(args[0])
        endpoints_requiring_permission[args[0]] = args[1]
        return func

    return inner


def requires_role(*args, **kwargs):
    def inner(func):
        requires_authentication(args[0])
        endpoints_requiring_role[args[0]] = args[1]
        return func

    return inner
