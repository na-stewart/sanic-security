from sanic import Blueprint
from sanic.response import file, text

from sanic_security.authentication import login, logout, register
from sanic_security.authorization import require_roles, require_permissions
from sanic_security.captcha import requires_captcha, request_captcha
from sanic_security.models import (
    CaptchaSession,
    TwoStepSession)
from sanic_security.recovery import (
    request_password_recovery,
    recover_password,
)
from sanic_security.utils import json
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
)

authentication = Blueprint("authentication_blueprint")
verification = Blueprint("verification_blueprint")
recovery = Blueprint("recovery_blueprint")
captcha = Blueprint("captcha_blueprint")
authorization = Blueprint("captcha_blueprint")  # For testing purposes only.
security = Blueprint.group(authentication, verification, recovery, captcha)


@authentication.post("api/auth/register")
@requires_captcha()
async def on_register(request, captcha_session):
    """
    Register an account with an email, username, and password. Once the account is created successfully, a two-step session is requested and the code is emailed.
    """
    two_step_session = await register(request)
    await two_step_session.email_code()
    response = json("Registration successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response


@authentication.post("api/auth/login")
async def on_login(request):
    """
    Login with an email and password.
    """
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, secure=False)
    return response


@authentication.post("api/auth/verify")
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    """
    Verify account with a two-step session code found in email.
    """
    await verify_account(two_step_session)
    return json("Account verification successful!", two_step_session.account.json())


@authentication.post("api/auth/logout")
async def on_logout(request):
    """
    Logout of logged in account.
    """
    authentication_session = await logout(request)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@verification.post("api/verif/resend")
async def on_resend_verification(request):
    """
    Resend existing two-step session code if lost.
    """
    two_step_session = await TwoStepSession().decode(request)
    await two_step_session.email_code()
    response = json("Verification resend successful!", two_step_session.account.json())
    return response


@verification.post("api/verif/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    """
    Request new two-step session and send email with code. Used if existing session is invalid or expired.
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
@requires_captcha()
async def on_recovery_request(request, captcha_session):
    """
    Requests new two-step session to ensure current recovery attempt is being made by account owner.
    """
    two_step_session = await request_password_recovery(request)
    await two_step_session.email_code()
    response = json("Recovery request successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response


@recovery.post("api/recov/recover")
@requires_two_step_verification()
async def on_recover(request, two_step_session):
    """
    Changes an account's password once recovery attempt was determined to have been made by account owner with two-step code found in email.
    """
    await recover_password(request, two_step_session)
    return json("Account recovered successfully", two_step_session.account.json())


@captcha.post("api/capt/request")
async def on_request_captcha(request):
    """
    Requests new captcha session.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response)
    return response


@captcha.get("api/capt/img")
async def on_captcha_img_request(request):
    """
    Retrieves captcha image from existing captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await file(captcha_session.get_image())


@authorization.get("api/auth/perms")
@require_permissions("admin:update")
async def on_require_perm(request, authentication_session):
    """
    Data retrieval example with wildcard authorization access.
    """
    return text("Admin who can only update gained access!")


@authorization.get("api/auth/roles")
@require_roles("Admin", "Mod")
async def on_require_role(request, authentication_session):
    """
    Data retrieval example with role authorization access.
    """
    return text("Admin or mod gained access!")