from sanic import Sanic, text
from tortoise.exceptions import IntegrityError

from sanic_security.authentication import register, login, requires_authentication
from sanic_security.authorization import require_roles, require_permissions
from sanic_security.blueprints import security
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account, Permission, Role
from sanic_security.recovery import request_password_recovery
from sanic_security.utils import json, hash_password
from sanic_security.verification import verify_account, two_step_verification, request_two_step_verification, \
    requires_two_step_verification

app = Sanic(__name__)


@app.post("api/test/auth/setup")
async def on_setup_test_account(request):
    if not await Account.filter(email="test3@test.com").exists():
        await Account.create(username="test", email="test@test.com", password=hash_password("testtest"), verified=True)
        setup_response = text("Test account successfully setup!")
    else:
        setup_response = text("Test account has already been setup!")

    return setup_response


@app.post("api/test/auth/register")
async def on_register(request):
    two_step_session = await register(request)
    response = json("Registration successful!", two_step_session.code)
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.json())
    if request.form.get("email") == "test@test.com":
        authentication_session.encode(response, False)
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    two_step_session = await two_step_verification(request)
    await verify_account(two_step_session)
    return json("Account verification successful!", two_step_session.account.json())


@app.post("api/test/auth/captcha/request")
async def on_captcha_request(request):
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response, False)
    return response


@app.post("api/test/auth/captcha/attempt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    return json("Captcha attempt successful!", captcha_session.json())


@app.post("api/test/auth/verification/request")
async def on_request_verification(request):
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/auth/verification/attempt")
@requires_two_step_verification()
async def on_verification_attempt(request, two_step_session):
    return json("Two step verification attempt successful!", two_step_session.json())


@app.post("api/test/auth/perms/assign")
@requires_authentication()
async def on_perms_assignment(request, authentication_session):
    if await Permission.filter(account=authentication_session.account).exists():
        assignment_response = json("Permissions already added to account!", authentication_session.account.json())
    else:
        await Permission.create(account=authentication_session.account, wildcard="admin:update")
        await Permission.create(account=authentication_session.account, wildcard="admin:add")
        assignment_response = json("Permissions added to account!", authentication_session.account.json())
    return assignment_response


@app.post("api/test/auth/roles/assign")
@requires_authentication()
async def on_roles_assignment(request, authentication_session):
    if await Role.filter(account=authentication_session.account).exists():
        assignment_response = json("Roles already added to account!", authentication_session.account.json())
    else:
        await Role.create(account=authentication_session.account, name="Admin")
        await Role.create(account=authentication_session.account, name="Mod")
        assignment_response = json("Roles added to account!", authentication_session.account.json())
    return assignment_response


@app.post("api/test/auth/perms/permit")
@require_permissions("admin:update")
async def on_permission_authorization_permit_attempt(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/auth/roles/permit")
@require_roles("Admin", "Mod")
async def on_role_authorization_permit_attempt(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/auth/recovery/request")
async def on_recovery_request(request):
    if not await Account.filter(email=request.form.get("email")).exists():
        await Account.create(username="test", email=request.form.get("email"), password=hash_password("testtest"),
                             verified=True)
    two_step_session = await request_password_recovery(request)
    response = json("Recovery request successful!", two_step_session.code)
    two_step_session.encode(response, False)
    return response


@app.post("api/auth/recovery/revert")
async def on_recovery_revert(request):
    """
    Changes an account's password once recovery attempt was determined to have been made by account owner with two-step code found in email.
    """
    account = await Account.filter(email=request.form.get("email")).first()
    account.password = hash_password("testtest")
    await account.save(update_fields=["password"])
    return json("Recovery reverted!", account.json())


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, workers=4)
