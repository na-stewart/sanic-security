from sanic import Sanic, text
from tortoise.exceptions import IntegrityError

from sanic_security.authentication import (
    login,
    on_second_factor,
    register,
    requires_authentication,
    logout,
)
from sanic_security.authorization import (
    require_permissions,
    require_roles,
    assign_role,
    assign_permission,
)
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.exceptions import SecurityError, UnverifiedError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account, Role
from sanic_security.utils import json, hash_password
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
)

app = Sanic(__name__)


@app.post("api/test/auth/register")
async def on_register(request):
    account = await register(
        request,
        verified=request.form.get("verified") == True,
        disabled=request.form.get("disabled") == True,
    )
    if account.verified:
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        response = json("Registration successful!", two_step_session.code)
        two_step_session.encode(response)
    else:
        response = json("Registration successful!", account.json())
    return response


@app.post("api/test/auth/login/two-factor")
async def on_login_with_two_factor_authentication(request):
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.account
    )
    await two_step_session.email_code()
    response = json(
        "Login successful! A second factor is now required to be authenticated.",
        two_step_session.code,
    )
    authentication_session.encode(response, False)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/auth/login/second-factor")
@requires_two_step_verification()
async def on_login_second_factor(request, two_step_verification):
    authentication_session = await on_second_factor(request)
    response = json(
        "Second factor attempt successful!", authentication_session.account.json()
    )
    return response


@app.post("api/test/auth/login/unverified")
async def on_login_with_verification_check(request):
    account = await Account.get_via_email(request.form.get("email"))
    try:
        authentication_session = await login(request, account)
    except UnverifiedError:
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        response = json("Verification required!", two_step_session.code)
        two_step_session.encode(response, False)
        return response
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, False)
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json(
        "You have verified your account and may login!", two_step_session.account.json()
    )


@app.post("api/test/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, False)
    return response


@app.post("api/test/auth/logout")
@requires_authentication()
async def on_logout(request, authentication_session):
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@app.post("api/test/auth")
@requires_authentication()
async def on_authenticate(request, authentication_session):
    response = json("Authenticated!", authentication_session.account.json())
    authentication_session.encode(response, False)
    return response


@app.post("api/test/capt/request")
async def on_captcha_request(request):
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response, False)
    return response


@app.post("api/test/capt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    return json("Captcha attempt successful!", captcha_session.json())


@app.post("api/test/two-step/request")
async def on_request_verification(request):
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/two-step/attempt")
@requires_two_step_verification()
async def on_verification_attempt(request, two_step_session):
    return json("Two step verification attempt successful!", two_step_session.json())


@app.post("api/test/auth/assign")
async def on_authorization_assign(request, authentication_session):
    response = text("Account assigned permissions.")
    if not await Role.filter(
        name="Admin", account=authentication_session.account
    ).exists():
        await assign_role("Admin", authentication_session.account)
        await assign_permission("admin:create", authentication_session.account)
    else:
        response = text("Account already assigned permissions.")
    return response


@app.post("api/test/auth/perms/sufficient")
@require_permissions("admin:create")
async def on_permission_authorization_sufficient(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/auth/perms/insufficient")
@require_permissions("admin:update")
async def on_permission_authorization_insufficient(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/auth/roles/sufficient")
@require_roles("Admin")
async def on_role_authorization_sufficient(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/auth/roles/insufficient")
@require_roles("Owner")
async def on_role_authorization_insufficient(request, authentication_session):
    return text("Account permitted.")


@app.post("api/test/account")
async def on_account_creation(request):
    try:
        account = await Account.create(
            username="test",
            email=request.form.get("email"),
            password=hash_password("testtest"),
            verified=True,
            disabled=False,
        )
        response = json("Account creation successful!", account.json())
    except IntegrityError:
        response = json(
            "Account creation has failed due to an expected integrity error!", None
        )
    return response


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, workers=4)
