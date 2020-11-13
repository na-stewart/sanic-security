from fnmatch import fnmatch

from amyrose.core.models import Role, Permission, InsufficientRoleError, \
    InsufficientPermissionsError

endpoints_requiring_role = {}
endpoints_requiring_permission = {}


async def authorize(authentication_session):
    pass


async def _check_role(authentication_session, authorized_role):
    if not await Role.filter(parent_uid=authentication_session.uid, role_name=authorized_role).exists():
        raise InsufficientRoleError('You do not have ' + authorized_role + ' access.', 403)


async def _check_permissions(authentication_session, authorized_permission):
    permissions = await Permission.filter(parent_uid=authentication_session.uid).all()
    for permission in permissions:
        if fnmatch(authorized_permission, permission):
            break
    else:
        raise InsufficientPermissionsError('You do not have the required permissions for this action.', 403)


def requires_permission(*args, **kwargs):
    def inner(func):
        if args[0] not in endpoints_requiring_permission:
            endpoints_requiring_permission[args[0]] = args[1]
        return func

    return inner


def requires_role(*args, **kwargs):
    def inner(func):
        if args[0] not in endpoints_requiring_role:
            endpoints_requiring_role[args[0]] = args[1]
        return func

    return inner
