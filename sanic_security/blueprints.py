from sanic import Blueprint

from sanic_security.authentication import (
    login,
    logout,
    register,
    requires_authentication,
)
from sanic_security.captcha import requires_captcha, request_captcha
from sanic_security.exceptions import UnverifiedError
from sanic_security.models import CaptchaSession, Account
from sanic_security.utils import json, config
from sanic_security.verification import (
    request_two_step_verification,
    verify_account,
)

security = Blueprint("security_blueprint")


@security.post(config["BLUEPRINT"]["register_route"])
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


@security.post(config["BLUEPRINT"]["login_route"])
async def on_login(request):
    """
    Login with an email and password. A two-step session will be requested for an account that is not verified on login and the code is emailed.
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


@security.post(config["BLUEPRINT"]["verify_route"])
async def on_verify(request):
    """
    Verify account with a two-step session code found in email.
    """
    two_step_session = await verify_account(request)
    return json("Account verification successful!", two_step_session.account.json())


@security.post(config["BLUEPRINT"]["logout_route"])
@requires_authentication()
async def on_logout(request, authentication_session):
    """
    Logout of logged in account.
    """
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.account.json())
    return response


@security.post(config["BLUEPRINT"]["captcha_request_route"])
async def on_request_captcha(request):
    """
    Requests new captcha session.
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response)
    return response


@security.get(config["BLUEPRINT"]["captcha_img_route"])
async def on_captcha_img_request(request):
    """
    Retrieves captcha image from existing captcha session.
    """
    captcha_session = await CaptchaSession().decode(request)
    return await captcha_session.get_image()
