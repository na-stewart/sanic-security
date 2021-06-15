from sanic import Blueprint, json
from sanic.response import file

from sanic_security.core.authentication import login, logout, register
from sanic_security.core.exceptions import UnverifiedError
from sanic_security.core.models import Account, VerificationSession, CaptchaSession
from sanic_security.core.recovery import (
    attempt_account_recovery,
    fulfill_account_recovery_attempt,
)
from sanic_security.core.verification import (
    request_two_step_verification,
    requires_captcha,
    requires_two_step_verification,
    verify_account,
    request_captcha,
)

authentication = Blueprint("authentication_blueprint")
verification = Blueprint("verification_blueprint")
recovery = Blueprint("recovery_blueprint")
captcha = Blueprint("captcha_blueprint")
security = Blueprint.group(authentication, verification, recovery, captcha)


@authentication.post("api/auth/register")
@requires_captcha()
async def on_register(request, captcha_session):
    """
    Register an account and email a verification code.
    """
    two_step_session = await register(request)
    await two_step_session.email_code()
    response = json("Registration successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response


@authentication.post("api/auth/login")
async def on_login(request):
    """
    Login with an email and password. If the account is unverified, request a verification session and email code.
    """
    account = await Account.get_via_email(request.form.get("email"))
    try:
        authentication_session = await login(request, account)
    except UnverifiedError as e:
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        two_step_session.encode(e.response)
        return e.response
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response)
    return response


@authentication.post("api/auth/verify")
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    """
    Verify account with existing verification session code.
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
    Resend existing verification session code.
    """
    two_step_session = await VerificationSession().decode(request)
    await two_step_session.email_code()
    response = json("Verification resend successful!", two_step_session.account.json())
    return response


@verification.post("api/verif/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    """
    Request new verification session.
    """
    two_step_session = await request_two_step_verification(request)
    await two_step_session.email_code()
    response = json("Verification request successful!", two_step_session.json())
    two_step_session.encode(response, secure=False)
    return response


@recovery.post("api/recov/request")
@requires_captcha()
async def on_recovery_request(request, captcha_session):
    """
    Attempts to recover account via changing password, requests verification to ensure the recovery attempt was made
    by account owner.
    """
    two_step_session = await attempt_account_recovery(request)
    await two_step_session.email_code()
    response = json("Recovery request successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response


@recovery.post("api/recov/fulfill")
@requires_two_step_verification()
async def on_recovery_fulfill(request, two_step_session):
    """
    Changes and recovers an account's password once recovery attempt was determined to have been made by account owner.
    """
    await fulfill_account_recovery_attempt(request, two_step_session)
    return json("Account recovered successfully", two_step_session.account.json())


@captcha.get("api/capt/request")
async def on_request_captcha(request):
    """
    Requests new captcha session.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response, secure=False)
    return response


@captcha.get("api/capt/img")
async def on_captcha_img(request):
    """
    Retrieves captcha image from existing captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await file(captcha_session.get_image())
