from sanic import Sanic, text

from sanic_security.authentication import register, login, requires_authentication
from sanic_security.authorization import require_permissions, require_roles
from sanic_security.blueprints import security
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account, Role, Permission
from sanic_security.utils import json
from sanic_security.verification import verify_account, two_step_verification, request_two_step_verification, \
    requires_two_step_verification

app = Sanic("__name__")


@app.post("api/test/auth/register")
async def on_register(request):
    two_step_session = await register(request)
    response = json("Registration successful!", two_step_session.code)
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    two_step_session = await two_step_verification(request)
    await verify_account(two_step_session)
    return json("Account verification successful!", two_step_session.account.json())


@app.post("api/test/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.json())
    authentication_session.encode(response, secure=False)
    return response


@app.post("api/test/capt/request")
async def on_captcha_request(request):
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response, False)
    return response


@app.post("api/test/capt/attempt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    return json("Captcha attempt successful!", captcha_session.json())


@app.post("api/test/verif/request")
async def on_request_verification(request):
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/verif/attempt")
@requires_two_step_verification()
async def on_verification_attempt(request, two_step_session):
    return json("Two step verification attempt successful!", two_step_session.json())


@app.post("api/test/autho/assign")
@requires_authentication()
async def on_authorization_assignment(request, authentication_session):
    if await Role.filter(account=authentication_session.account).exists() or await Permission.filter(account=authentication_session.account).exists():
        assignment_response = json("Roles and permissions already added to account!", authentication_session.account.json())
    else:
        await Role.create(account=authentication_session.account, name="Admin")
        await Role.create(account=authentication_session.account, name="Mod")
        await Permission.create(account=authentication_session.account, wildcard="admin:update")
        await Permission.create(account=authentication_session.account, wildcard="admin:add")
        assignment_response = json("Roles and permissions added to account!", authentication_session.account.json())
    return assignment_response


@app.post("api/test/autho/perms")
@require_permissions("admin:update")
async def on_permissions_attempt(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/autho/roles")
@require_roles("Admin", "Mod")
async def on_role_attempt(request, authentication_session):
    return text("Account permitted.")


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, workers=4)
