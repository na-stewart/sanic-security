from fnmatch import fnmatch

from amyrose.core.models import AuthenticationSession, Role, Permission, InsufficientRoleError, \
    InsufficientPermissionsError


async def account_authorized(request, authorized_role=None, authorized_permission=None):
    if authorized_role:
        await _check_role(request, authorized_role)
    else:
        await _check_permissions(request, authorized_permission)


async def _check_role(request, authorized_role):
    if not await Role.filter(parent_uid=await get_account_uid(request), role_name=authorized_role).exists():
        raise InsufficientRoleError('You do not have ' + authorized_role + ' access.', 403)


async def _check_permissions(request, authorized_permission):
    permissions = await Permission.filter(parent_uid=await get_account_uid(request)).all()
    for permission in permissions:
        if fnmatch(authorized_permission, permission):
            break
    else:
        raise InsufficientPermissionsError('You do not have the required permissions for this action.', 403)


async def get_account_uid(request):
    token = request.cookies.get("authtkn")
    session = await AuthenticationSession.filter(token=token).first()
    return session.parent_uid
