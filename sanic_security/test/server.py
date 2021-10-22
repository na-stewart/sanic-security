from argon2 import PasswordHasher
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
    assign_role,
    assign_permission,
    check_permissions,
    check_roles,
)
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account, Role, Permission, SessionFactory
from sanic_security.utils import json
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
)

app = Sanic(__name__)
session_factory = SessionFactory()
password_hasher = PasswordHasher()


@app.post("api/test/auth/register")
async def on_register(request):
    """
    Register an account with email and password. If unverified, a two_step session code is provided in the response.
    """
    account = await register(
        request,
        verified=request.form.get("verified") == "true",
        disabled=request.form.get("disabled") == "true",
    )
    if not account.verified:
        two_step_session = await request_two_step_verification(request, account)
        response = json(
            "Registration successful! Verification required.", two_step_session.code
        )
        two_step_session.encode(response)
    else:
        response = json("Registration successful!", account.json())
    return response


@app.post("api/test/auth/login/two-factor")
async def on_login_with_two_factor_authentication(request):
    """
    Login with a two-factor requirement.
    """
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.account
    )
    response = json(
        "Login successful! A second factor is now required to be authenticated.",
        two_step_session.code,
    )
    authentication_session.encode(response)
    two_step_session.encode(response)
    return response


@app.post("api/test/auth/login/second-factor")
@requires_two_step_verification()
async def on_login_second_factor(request, two_step_verification):
    """
    Removes the second factor requirement from the client authentication session when the two-step verification attempt
    is successful.
    """
    authentication_session = await on_second_factor(request)
    response = json(
        "Second factor attempt successful!", authentication_session.account.json()
    )
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    """
    Verifies an unverified account.
    """
    two_step_session = await verify_account(request)
    return json(
        "You have verified your account and may login!", two_step_session.account.json()
    )


@app.post("api/test/auth/login")
async def on_login(request):
    """
    Login to an account with an email and password. Authentication session is then created and encoded.
    """
    account = await Account.get_via_email(request.form.get("email"))
    authentication_session = await login(request, account)
    response = json("Login successful!", account.json())
    authentication_session.encode(response)
    return response


@app.post("api/test/auth/logout")
@requires_authentication()
async def on_logout(request, authentication_session):
    """
    Logout of currently logged in account.
    """
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@app.post("api/test/auth")
@requires_authentication()
async def on_authenticate(request, authentication_session):
    """
    Check if current authentication session is valid.
    """
    response = json("Authenticated!", authentication_session.account.json())
    authentication_session.encode(response)
    return response


@app.post("api/test/capt/request")
async def on_captcha_request(request):
    """
    Request captcha with solution in the response.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response)
    return response


@app.post("api/test/capt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    """
    Captcha challenge.
    """
    return json("Captcha attempt successful!", captcha_session.json())


@app.post("api/test/two-step/request")
async def on_request_verification(request):
    """
    Two-step verification is requested with code in the response.
    """
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response)
    return response


@app.post("api/test/two-step")
@requires_two_step_verification()
async def on_verification_attempt(request, two_step_session):
    """
    Attempt two-step verification.
    """
    return json("Two step verification attempt successful!", two_step_session.json())


@app.post("api/test/auth/perms/assign")
@requires_authentication()
async def on_authorization_assign_perms(request, authentication_session):
    """
    Permissions assigned to logged in account.
    """
    response = text("Account assigned permissions.")
    if not await Permission.filter(
        wildcard="admin:create", account=authentication_session.account
    ).exists():
        await assign_permission("admin:create", authentication_session.account)
    else:
        response = text("Account already assigned permissions.")
    return response


@app.post("api/test/auth/perms")
async def on_permissions_authorization(request):
    """
    Permissions authorization.
    """
    await check_permissions(request, request.form.get("permissions"))
    return text("Account permitted.")


@app.post("api/test/auth/roles/assign")
@requires_authentication()
async def on_authorization_assign_role(request, authentication_session):
    """
    Roles assigned to client.
    """
    response = text("Account assigned role.")
    if not await Role.filter(
        name="Admin", account=authentication_session.account
    ).exists():
        await assign_role("Admin", authentication_session.account)
    else:
        response = text("Account already assigned role.")
    return response


@app.post("api/test/auth/roles")
async def on_roles_authorization(request):
    """
    Roles authorization.
    """
    await check_roles(request, request.form.get("roles"))
    return text("Account permitted.")


@app.post("api/test/account")
async def on_account_creation(request):
    """
    Easily creates a usable account.
    """
    try:
        account = await Account.create(
            username="test",
            email=request.form.get("email"),
            password=password_hasher.hash("testtest"),
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
