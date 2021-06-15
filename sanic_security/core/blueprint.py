from sanic import Blueprint, json
from sanic.response import file

from sanic_security.core.authentication import login, logout, register
from sanic_security.core.exceptions import UnverifiedError
from sanic_security.core.models import Account, VerificationSession, CaptchaSession
from sanic_security.core.recovery import attempt_account_recovery, fulfill_account_recovery_attempt
from sanic_security.core.verification import request_two_step_verification, requires_captcha, \
    requires_two_step_verification, verify_account, request_captcha

security_blueprint = Blueprint("security_blueprint")


@security_blueprint.post('api/auth/register')
@requires_captcha()
async def on_register(request, captcha_session):
    two_step_session = await register(request)
    await two_step_session.email_code()
    response = json('Registration successful!', two_step_session.account.json())
    two_step_session.encode(response)
    return response


@security_blueprint.post('api/auth/login')
async def on_login(request):
    account = await Account.get_via_email(request.form.get('email'))
    try:
        authentication_session = await login(request, account)
    except UnverifiedError as e:
        # Requests for account to verify themselves if verification failed on previous login/register attempt.
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        two_step_session.encode(e.response)
        return e.response
    response = json('Login successful!', authentication_session.account.json())
    authentication_session.encode(response)
    return response


@security_blueprint.post('api/auth/verify')
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    await verify_account(two_step_session)
    return json('Account verification successful!', two_step_session.account.json())


@security_blueprint.post('api/auth/logout')
async def on_logout(request):
    authentication_session = await logout(request)
    response = json('Logout successful!', authentication_session.account.json())
    return response


@security_blueprint.post('api/verification/resend')
async def on_resend_verification(request):
    two_step_session = await VerificationSession().decode(request)
    await two_step_session.email_code()
    response = json('Verification resend successful!', two_step_session.account.json())
    return response


@security_blueprint.post("api/verification/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    two_step_session = await request_two_step_verification(request)
    await two_step_session.email_code()
    response = json("Verification request successful!", two_step_session.json())
    two_step_session.encode(response, secure=False)
    return response


@security_blueprint.post('api/recovery/request')
@requires_captcha()
async def on_recovery_request(request, captcha_session):
    two_step_session = await attempt_account_recovery(request)
    await two_step_session.email_code()
    response = json('Recovery request successful!', two_step_session.account.json())
    two_step_session.encode(response)
    return response


@security_blueprint.post("api/recovery/fulfill")
@requires_two_step_verification()
async def on_recovery_fulfill(request, two_step_session):
    """
    Changes and recovers an account's password once recovery attempt was determined to have been made by account owner.
    """
    await fulfill_account_recovery_attempt(request, two_step_session)
    return json("Account recovered successfully", two_step_session.account.json())


@security_blueprint.get("api/captcha/request")
async def on_request_captcha(request):
    """
    Requests captcha session for client.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response, secure=False)
    return response


@security_blueprint.get("api/captcha/img")
async def on_captcha_img(request):
    """
    Retrieves captcha image from captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await file(captcha_session.get_image())
