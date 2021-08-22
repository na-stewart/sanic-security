from sanic import Sanic, text
from tortoise.exceptions import IntegrityError

from sanic_security.authentication import (
    register,
    login,
    requires_authentication,
    validate_second_factor,
)
from sanic_security.authorization import require_roles, require_permissions
from sanic_security.blueprints import security
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account, Permission, Role
from sanic_security.utils import json, hash_password
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
)

app = Sanic(__name__)


@app.post("api/test/auth")
@requires_authentication()
async def on_authenticate(request, authentication_session):
    """
    Test if client is authenticated.
    """
    response = json("Authentication successful!", authentication_session.account.json())
    return response


@app.post("api/test/auth/register")
async def on_register(request):
    """
    Register an account with an email, username, and password. Once the account is created successfully, a two-step session is requested and the code is provided in the response.
    """
    two_step_session = await register(request)
    response = json("Registration successful!", two_step_session.code)
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/auth/login")
async def on_login(request):
    """
    Login with an email and password.
    """
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.json())
    authentication_session.encode(response, False)
    return response


@app.post("api/test/auth/login/two-factor")
async def on_two_factor_login(request):
    """
    Login with an email and password with a second factor requirement.
    """
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.account
    )
    response = json("Login successful!", two_step_session.code)
    authentication_session.encode(response, False)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/auth/login/second-factor")
@requires_two_step_verification()
async def on_second_factor(request, two_step_verification):
    """
    Second factor in the two-factor authentication process.
    """
    authentication_session = await validate_second_factor(request)
    response = json("Second factor successful!", authentication_session.json())
    return response


@app.post("api/test/capt/request")
async def on_captcha_request(request):
    """
    Requests new captcha session.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response, False)
    return response


@app.post("api/test/capt/attempt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    """
    Captcha challenge attempt using the captcha provided in the captcha request response.
    """
    return json("Captcha attempt successful!", captcha_session.json())


@app.post("api/test/verif/request")
async def on_request_verification(request):
    """
    Requests new two-step session.
    """
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/verif/attempt")
@requires_two_step_verification()
async def on_verification_attempt(request, two_step_session):
    """
    Two-step verification attempt using the captcha provided in the verification request response.
    """
    return json("Two step verification attempt successful!", two_step_session.json())


@app.post("api/test/auth/perms/assign")
@requires_authentication()
async def on_perms_assignment(request, authentication_session):
    """
    Assigns permissions to a logged in test account.
    """
    if await Permission.filter(account=authentication_session.account).exists():
        assignment_response = json(
            "Permissions already added to account!",
            authentication_session.account.json(),
        )
    else:
        await Permission.create(
            account=authentication_session.account, wildcard="admin:permit"
        )
        assignment_response = json(
            "Permissions added to account!", authentication_session.account.json()
        )
    return assignment_response


@app.post("api/test/auth/roles/assign")
@requires_authentication()
async def on_roles_assignment(request, authentication_session):
    """
    Assigns roles to a logged in test account.
    """
    if await Role.filter(account=authentication_session.account).exists():
        assignment_response = json(
            "Roles already added to account!", authentication_session.account.json()
        )
    else:
        await Role.create(account=authentication_session.account, name="Permit")
        assignment_response = json(
            "Roles added to account!", authentication_session.account.json()
        )
    return assignment_response


@app.post("api/test/auth/perms/permit")
@require_permissions("admin:permit")
async def on_permission_authorization_permit_attempt(request, authentication_session):
    """
    Authorization with permissions provided to the test account.
    """
    return text("Account permitted.")


@app.post("api/test/auth/perms/deny")
@require_permissions("admin:deny")
async def on_permission_authorization_deny_attempt(request, authentication_session):
    """
    Authorization with insufficient permissions provided to the test account.
    """
    return text("Account permitted.")


@app.post("api/test/auth/roles/permit")
@require_roles("Permit")
async def on_role_authorization_permit_attempt(request, authentication_session):
    """
    Authorization with roles provided to the test account.
    """
    return text("Account permitted.")


@app.post("api/test/auth/roles/deny")
@require_roles("Deny")
async def on_role_authorization_deny_attempt(request, authentication_session):
    """
    Authorization with insufficient roles provided to the test account.
    """
    return text("Account permitted.")


@app.post("api/test/account/create")
async def on_account_creation(request):
    """
    Creates an account to be used for testing purposes.
    """
    form = request.form
    try:
        account = await Account.create(
            username="test",
            email=form.get("email"),
            password=hash_password("password"),
            verified=True,
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
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, workers=4)
