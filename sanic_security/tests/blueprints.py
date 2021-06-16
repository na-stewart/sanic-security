from sanic import Blueprint
from sanic.response import file, text

from sanic_security.core.authentication import (
    login,
    logout,
    register,
    requires_authentication,
)
from sanic_security.core.authorization import require_roles, require_permissions
from sanic_security.core.exceptions import UnverifiedError
from sanic_security.core.models import (
    Account,
    VerificationSession,
    CaptchaSession,
    TwoStepSession,
    json,
    Permission,
    Role,
)
from sanic_security.core.recovery import (
    attempt_recovery,
    fulfill_recovery_attempt,
)
from sanic_security.core.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
    request_captcha,
    requires_captcha,
)

authentication = Blueprint("test_authentication_blueprint")
authorization = Blueprint("test_authorization_blueprint")
verification = Blueprint("test_verification_blueprint")
recovery = Blueprint("test_recovery_blueprint")
captcha = Blueprint("test_captcha_blueprint")
security = Blueprint.group(
    authentication, authorization, verification, recovery, captcha
)


@authentication.post("api/auth/register")
async def on_register(request):
    """
    Register an account with an email, username, and password. Once account is created successfully, a two-step session is requested and the code is emailed.
    """
    two_step_session = await register(request)
    await two_step_session.email_code()
    response = json("Registration successful!", two_step_session.account.json())
    two_step_session.encode(response, secure=False)
    return response


@authentication.post("api/auth/login")
async def on_login(request):
    """
    Login with an email and password. If the account is unverified, request a two-step session and email code.
    """
    account = await Account.get_via_email(request.form.get("email"))
    try:
        authentication_session = await login(request, account)
    except UnverifiedError as e:
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        two_step_session.encode(e.response, secure=False)
        return e.response
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, secure=False)
    return response


@authentication.post("api/auth/verify")
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    """
    Verify account with a two-step code found in email.
    """
    await verify_account(two_step_session)
    return json("Account verification successful!", two_step_session.account.json())


@authentication.post("api/auth/logout")
async def on_logout(request):
    """
    Logout logged in account.
    """
    authentication_session = await logout(request)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@verification.post("api/verif/resend")
async def on_resend_verification(request):
    """
    Resend existing two-step session code if lost.
    """
    two_step_session = await VerificationSession().decode(request)
    await two_step_session.email_code()
    response = json("Verification resend successful!", two_step_session.account.json())
    return response


@verification.post("api/verif/request")
async def on_request_verification(request):
    """
    Request new two-step session and send email with code if existing session is invalid or expired.
    """
    existing_two_step_session = await TwoStepSession().decode(request)
    two_step_session = await request_two_step_verification(
        request, existing_two_step_session.account
    )
    await two_step_session.email_code()
    response = json("Verification request successful!", two_step_session.json())
    two_step_session.encode(response, secure=False)
    return response


@recovery.post("api/recov/request")
async def on_recovery_request(request):
    """
    Requests new two-step session to ensure current recovery attempt is being made by account owner.
    """
    two_step_session = await attempt_recovery(request)
    await two_step_session.email_code()
    response = json("Recovery request successful!", two_step_session.account.json())
    two_step_session.encode(response, secure=False)
    return response


@recovery.post("api/recov/fulfill")
@requires_two_step_verification()
async def on_recovery_fulfill(request, two_step_session):
    """
    Changes and recovers an account's password once recovery attempt was determined to have been made by account owner with two-step session code found in email.
    """
    await fulfill_recovery_attempt(request, two_step_session)
    return json("Account recovered successfully", two_step_session.account.json())


@captcha.post("api/capt/request")
async def on_request_captcha(request):
    """
    Requests new captcha session.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response, secure=False)
    return response


@captcha.post("api/capt/fulfill")
@requires_captcha()
async def on_captcha_fulfill(request, captcha_session):
    """
    Data retrieval with captcha based verification.
    """
    return text("User who is confirmed not a robot has now gained access!")


@captcha.get("api/capt/img")
async def on_captcha_img_request(request):
    """
    Requests captcha image from existing captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await file(captcha_session.get_image())


@authorization.get("api/auth/perms")
@require_permissions("admin:update")
async def on_require_perm(request, authentication_session):
    """
    Data retrieval with wildcard based authorization access.
    """
    return text("Admin who can only update gained access!")


@authorization.get("api/auth/roles")
@require_roles("Admin", "Mod")
async def on_require_role(request, authentication_session):
    """
    Data retrieval with role based authorization access.
    """
    return text("Admin or mod gained access!")


@authorization.post("api/auth/perms")
@requires_authentication()
async def on_create_admin_perms(request, authentication_session):
    """
    Creates 'admin:update' and 'admin:add' permissions to be used for testing wildcard based authorization.
    """
    await Permission().create(
        account=authentication_session.account, wildcard="admin:update", decription=""
    )
    await Permission().create(
        account=authentication_session.account, wildcard="admin:add"
    )
    return json(
        "Permissions added to your account!", authentication_session.account.json()
    )


@authorization.post("api/auth/roles")
@requires_authentication()
async def on_create_admin_roles(request, authentication_session):
    """
    Creates 'Admin' and 'Mod' roles to be used for testing role based authorization.
    """
    await Role().create(account=authentication_session.account, name="Admin")
    await Role().create(account=authentication_session.account, name="Mod")
    return json("Roles added to your account!", authentication_session.account.json())
