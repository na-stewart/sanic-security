from argon2 import PasswordHasher
from sanic import Sanic, text
from tortoise.contrib.sanic import register_tortoise
from tortoise.exceptions import IntegrityError

from sanic_security.authentication import (
    login,
    on_second_factor,
    register,
    requires_authentication,
    logout,
    refresh_authentication,
)
from sanic_security.authorization import (
    assign_role,
    check_permissions,
    check_roles,
)
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.configuration import config as security_config
from sanic_security.exceptions import SecurityError
from sanic_security.models import Account, Role, SessionFactory
from sanic_security.utils import json
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
)

app = Sanic("test")
session_factory = SessionFactory()
password_hasher = PasswordHasher()


@app.post("api/test/auth/register")
async def on_register(request):
    """
    Register an account with email and password.
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


@app.post("api/test/auth/verify")
async def on_verify(request):
    """
    Verifies an unverified account.
    """
    two_step_session = await verify_account(request)
    return json(
        "You have verified your account and may login!", two_step_session.bearer.json()
    )


@app.post("api/test/auth/login")
async def on_login(request):
    """
    Login to an account with an email and password.
    """
    authentication_session = await login(
        request, two_factor=request.form.get("two_factor") == "true"
    )
    if request.form.get("two_factor") == "true":
        two_step_session = await request_two_step_verification(
            request, authentication_session.bearer
        )
        response = json(
            "Login successful! Second factor required.", two_step_session.code
        )
        two_step_session.encode(response)
    else:
        response = json("Login successful!", authentication_session.bearer.json())
    authentication_session.encode(response)
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
        "Second factor attempt successful!", authentication_session.bearer.json()
    )
    return response


@app.post("api/test/auth/refresh")
async def on_refresh(request):
    """
    Refresh client authentication session with a new session via the client session's refresh token. However, the new authentication
    session is never encoded. Due to the fact that the new session isn't encoded, attempting to refresh again will
    result in an error as a refresh token should only be used once.
    """
    refreshed_authentication_session = await refresh_authentication(request)
    response = json(
        "Authentication session refreshed!",
        refreshed_authentication_session.bearer.json(),
    )
    return response


@app.post("api/test/auth/logout")
@requires_authentication()
async def on_logout(request, authentication_session):
    """
    Logout of currently logged in account.
    """
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.bearer.json())
    return response


@app.post("api/test/auth")
@requires_authentication()
async def on_authenticate(request, authentication_session):
    """
    Check if current authentication session is valid.
    """
    response = json("Authenticated!", authentication_session.bearer.json())
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


@app.post("api/test/auth/roles")
@requires_authentication()
async def on_authorization(request, authentication_session):
    """
    Permissions authorization.
    """
    await check_roles(request, request.form.get("role"))
    if request.form.get("permissions_required"):
        await check_permissions(
            request, *request.form.get("permissions_required").split(", ")
        )
    return text("Account permitted.")


@app.post("api/test/auth/roles/assign")
@requires_authentication()
async def on_role_assign(request, authentication_session):
    """
    Assigns authenticated account a role.
    """
    await assign_role(
        request.form.get("name"),
        "Role used for testing.",
        request.form.get("permissions"),
        authentication_session.bearer,
    )
    return text("Role assigned.")


@app.post("api/test/account")
async def on_account_creation(request):
    """
    Creates a usable account.
    """
    try:
        username = "test"
        if request.form.get("username"):
            username = request.form.get("username")
        account = await Account.create(
            username=username,
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
    return exception.json_response


security_config.SECRET = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6
ugBN9e1hw7v2z2PwmJENhYrqbBHU4vHCHEEZjdZIQRqwriFpeeoqMA1ecgwJz3fO
uYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep
9hp4XLF87QlDVDrZIStfVn25+ZfSfKH+WYBUglZBmz/K6uW41mSRuuH3Pu/lnPgG
vsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbD
Ta8CNiGI251QMHlkstd6FFYu5lJQcuppOm79iQIDAQABAoIBAACRz1RBMmV9ruIF
WtcNu24u1SBw8FAniW4SGuPBbxeg1KcmOlegx3IdkBhG7j9hBF5+S/3ZhGTGhYdg
lYcS2aSMK0Q6ofd4NDMk+bzlIdEZNTVbTnlle1vBjVjxOoIP7aL6mC/HFO7T+SYq
jIGkjsxYFHf1DFu0nHS5OA/rOoEt1SZA5DO0dCd1IjuPvKsvJIRErjnFuW6bs9K7
XNpE2gHKvtvzVFRQC2F7AY7b45cx6QZ08yCbToITRI59RzGgrpqIsJI0N5yT96DU
ALQDkAJz4XzhS8+bHoCDGeTPfJLq4xXcLrtFSk5Mhp4eIOPCI/fv3IO8JnSopgeP
+y+NeFMCgYEA/rq0R5v9JuxtcbXsFXua5KWoDojOvHkeP93F5eGSDu8iRo/4zhyH
WGhZuMIuMARAOJ7tAyWxDTzoSILhC4+fF6WQJKiBIlLLGXFyJ9qgq2eN+Z/b9+k6
PotQV9zunmIN8vuCrtPBlVbOMrofGHG85zSDyDDDUXZoh7ko8tJ3nosCgYEAxAb/
8E/fmEADxJZSFoqwlElXm6h7sfThrhjf12ENwBv7AvH8XsiNVQsIGnoVxeHQJ7U0
pROucD/iykf8I9+ou9ZBQyfoRJiOkzExeMWEyhmGyGmcNCZ1kKK/RZu6Bks/Eoqn
pVH9bUjjAwSXeFRZE3zfsAclQr3BYjqFjQzuSrsCgYEA7RhLBPwkPT6C//wcqkJK
gdfO/PhJtRPnG/sIYFf84vmiJZuMMgxLzfYSzO2wn/DU9d63LN7AVVoDurpXTbN4
mUH5UKWmzJPThvMZFg9gzSmt9FLfI3lqRRzWw3FYiQMriKahlKh03tPVSVID73Su
J2Wx43u/0OstkGa/voQ34tECgYA+G2mjnerdtgp7kpTXh4GCueoD61GlhEyseD0T
ZDCTGUpiGIE5FpmQxDoBCYU0eOMWcZcIZj/yWItmQ4BjbU1slel/eXlhomQpxoBC
H3J/Ba9qd+uBql29QZMQXtKFg/mryjprapq8sUcbgazr9u1x+zJz9w+bIbvPf3Mo
yVwGWQKBgQDXKMG9fV+/61imgsOZTyd2ld8MnIWAeUGgk5e6P+niAOPGFSPue3Fg
GvLURiJtuu05dM9U9pQhtGVrCwHcT9Yixiwpnyw31DQp3uU91DhrtHyRIf3H/ywr
WLwY4Z+TsktW6UPoe2cyGbN1G1CHHo/vq8zPNkVWmhciIUeHR3YJbw==
-----END RSA PRIVATE KEY-----
"""
security_config.PUBLIC_SECRET = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww3pEiUx6wMFawJNAHCI
80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU4vHCHEEZ
jdZIQRqwriFpeeoqMA1ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvs
jsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStfVn25+ZfSfKH+WYBU
glZBmz/K6uW41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6
LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251QMHlkstd6FFYu5lJQcuppOm79
iQIDAQAB
-----END PUBLIC KEY-----
"""
security_config.SESSION_ENCODING_ALGORITHM = "RS256"
security_config.ALLOW_LOGIN_WITH_USERNAME = True
security_config.SESSION_EXPIRES_ON_CLIENT = True
security_config.AUTHENTICATION_SESSION_EXPIRATION = 0
register_tortoise(
    app,
    db_url=security_config.TEST_DATABASE_URL,
    modules={"models": ["sanic_security.models"]},
    generate_schemas=True,
)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True, workers=1)
