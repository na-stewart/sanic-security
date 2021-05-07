from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import json as sanic_json
from sanic.response import text, file

from sanic_security.core.authentication import (
    register,
    login,
    requires_authentication,
    logout,
)
from sanic_security.core.authorization import require_permissions, require_roles
from sanic_security.core.initializer import initialize_security
from sanic_security.core.models import (
    SecurityError,
    Permission,
    Role,
    CaptchaSession,
    TwoStepSession,
)
from sanic_security.core.recovery import (
    attempt_account_recovery,
    fulfill_account_recovery_attempt,
)
from sanic_security.core.utils import xss_prevention_middleware
from sanic_security.core.verification import (
    requires_captcha,
    request_captcha,
    requires_two_step_verification,
    verify_account,
    request_two_step_verification,
)

app = Sanic("Sanic Security Test Server")


def json(message, data, status_code=200):
    payload = {"message": message, "status_code": status_code, "data": data}
    return sanic_json(payload, status=status_code)


def check_for_empty(form, *args):
    for key, value in form.items():
        if value is not None:
            if not isinstance(value[0], bool) and not value[0] and key not in args:
                raise ServerError(key + " is empty!", 400)


@app.middleware("response")
async def xxs_middleware(request, response):
    """
    Response middleware test.
    """
    xss_prevention_middleware(request, response)


@app.post("api/test/register")
async def on_register(request):
    """
    Registration test without verification or captcha requirements.
    """
    account = await register(request, verified=True)
    return json("Registration Successful!", account.json())


@app.post("api/test/register/verification")
@requires_captcha()
async def on_register_verification(request, captcha_session):
    """
    Registration test with all built-in requirements.
    """
    two_step_session = await register(request)
    await two_step_session.text_code()
    response = json("Registration successful", two_step_session.account.json())
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/register/verify")
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    """
    Attempt to verify account and allow access if unverified.
    """
    await verify_account(two_step_session)
    return json("Verification successful!", two_step_session.json())


@app.get("api/test/captcha/img")
async def on_captcha_img(request):
    """
    Retrieves captcha image from captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await file(captcha_session.get_image())


@app.get("api/test/captcha")
async def on_request_captcha(request):
    """
    Requests captcha session for client.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response, secure=False)
    return response


@app.post("api/test/verification/resend")
async def resend_verification_request(request):
    """
    Resends verification code if somehow lost.
    """
    two_step_session = await TwoStepSession().decode(request)
    await two_step_session.text_code()
    return json("Verification code resend successful", two_step_session.json())


@app.post("api/test/verification/request")
@requires_captcha()
async def new_verification_request(request, captcha_session):
    """
    Creates new verification code.
    """

    two_step_session = await request_two_step_verification(request)
    await two_step_session.text_code()
    response = json("Verification request successful", two_step_session.json())
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/login")
async def on_login(request):
    """
    User login, creates and encodes authentication session.
    """
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, secure=False)
    return response


@app.post("api/test/logout")
async def on_logout(request):
    """
    User logout, invalidates client authentication session.
    """
    authentication_session = await logout(request)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@app.post("api/test/role/admin")
@requires_authentication()
async def on_create_admin(request, authentication_session):
    """
    Creates 'Admin' and 'Mod' roles to be used for testing role based authorization.
    """
    client = authentication_session.account
    await Role().create(account=client, name="Admin")
    await Role().create(account=client, name="Mod")
    return json("Roles added to your account!", client.json())


@app.post("api/test/perms/admin")
@requires_authentication()
async def on_create_admin_perm(request, authentication_session):
    """
    Creates 'admin:update' and 'admin:add' permissions to be used for testing wildcard based authorization.
    """
    client = authentication_session.account
    await Permission().create(account=client, wildcard="admin:update", decription="")
    await Permission().create(account=client, wildcard="admin:add")
    return json("Permissions added to your account!", client.json())


@app.get("api/test/client")
@requires_authentication()
async def on_test_client(request, authentication_session):
    """
    Retrieves authenticated client username.
    """
    return text("Hello " + authentication_session.account.username + "!")


@app.get("api/test/perm")
@require_permissions("admin:update")
async def on_test_perm(request, authentication_session):
    """
    Tests client wildcard permissions authorization access.
    """
    return text("Admin who can only update gained access!")


@app.get("api/test/role")
@require_roles("Admin", "Mod")
async def on_test_role(request, authentication_session):
    """
    Tests client role authorization access.
    """
    return text("Admin gained access!")


@app.post("api/test/recovery/attempt")
@requires_captcha()
async def on_recovery_attempt(request, captcha_session):
    """
    Attempts to recover account via changing password, requests verification to ensure the recovery attempt was made
    by account owner.
    """
    two_step_session = await attempt_account_recovery(request)
    await two_step_session.text_code()
    response = json(
        "A recovery attempt has been made, please verify account ownership.",
        two_step_session.json(),
    )
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/recovery/fulfill")
@requires_two_step_verification()
async def on_recovery_fulfill(request, two_step_session):
    """
    Changes and recovers an account's password once recovery attempt was determined to have been made by account owner.
    """
    await fulfill_account_recovery_attempt(request, two_step_session)
    return json("Account recovered successfully", two_step_session.account.json())


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


if __name__ == "__main__":
    initialize_security(app)
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
