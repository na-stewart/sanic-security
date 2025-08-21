import datetime
import traceback

from httpx_oauth.clients.google import GoogleOAuth2
from sanic import Sanic, text, raw, redirect
from tortoise.contrib.sanic import register_tortoise

from sanic_security.authentication import (
    login,
    register,
    requires_authentication,
    logout,
    fulfill_second_factor,
    initialize_security,
)
from sanic_security.authorization import (
    assign_role,
    check_permissions,
    check_roles,
)
from sanic_security.configuration import config
from sanic_security.exceptions import SecurityError
from sanic_security.models import Account, CaptchaSession, AuthenticationSession
from sanic_security.oauth import (
    oauth_encode,
    initialize_oauth,
    oauth_callback,
    oauth_decode,
    oauth_revoke,
)
from sanic_security.utils import json, str_to_bool, password_hasher
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
    requires_captcha,
)

"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

app = Sanic("tests")
google_oauth = GoogleOAuth2(config.OAUTH_CLIENT, config.OAUTH_SECRET)


@app.post("api/test/auth/register")
async def on_register(request):
    """Register an account with email and password."""
    account = await register(
        request,
        verified=str_to_bool(request.form.get("verified")),
        disabled=str_to_bool(request.form.get("disabled")),
    )
    if not account.verified:
        two_step_session = await request_two_step_verification(request, account, "2fa")
        response = json(
            "Registration successful! Verification required.", two_step_session.code
        )
        two_step_session.encode(response)
    else:
        response = json("Registration successful!", account.json)
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    """Verifies client account."""
    two_step_session = await verify_account(request)
    return json(
        "You have verified your account and may login!", two_step_session.bearer.json
    )


@app.post("api/test/auth/login")
async def on_login(request):
    """Login to an account with an email and password."""
    authentication_session = await login(
        request,
        require_second_factor=str_to_bool(
            request.args.get("two-factor-authentication")
        ),
    )
    if str_to_bool(request.args.get("two-factor-authentication")):
        two_step_session = await request_two_step_verification(
            request, authentication_session.bearer
        )
        response = json(
            "Login successful! Two-factor authentication required.",
            two_step_session.code,
        )
        two_step_session.encode(response)
    else:
        response = json("Login successful!", authentication_session.json)
    authentication_session.encode(response)
    return response


@app.post("api/test/auth/login/anon")
async def on_login_anonymous(request):
    """Login as anonymous user."""
    authentication_session = await AuthenticationSession.new(request)
    response = json(
        "Anonymous user now associated with session!", authentication_session.json
    )
    authentication_session.encode(response)
    return response


@app.post("api/test/auth/validate-2fa")
async def on_two_factor_authentication(request):
    """Fulfills client authentication session's second factor requirement."""
    authentication_session = await fulfill_second_factor(request)
    response = json(
        "Authentication session second-factor fulfilled! You are now authenticated.",
        authentication_session.bearer.json,
    )
    return response


@app.post("api/test/auth/logout")
async def on_logout(request):
    """Logout of currently logged in account."""
    authentication_session = await logout(request)
    await oauth_revoke(request, google_oauth)
    response = json("Logout successful!", authentication_session.json)
    return response


@app.post("api/test/auth")
@requires_authentication
async def on_authenticate(request):
    """Authenticate client session and account."""
    response = json(
        "Authenticated!",
        {
            "bearer": (
                request.ctx.session.bearer.json
                if not request.ctx.session.anonymous
                else None
            ),
            "refresh": request.ctx.session.is_refresh,
        },
    )
    return response


@app.post("api/test/auth/expire")
@requires_authentication
async def on_authentication_expire(request):
    """Expire client's session."""
    request.ctx.session.expiration_date = datetime.datetime.now(datetime.UTC)
    await request.ctx.session.save(update_fields=["expiration_date"])
    return json("Authentication expired!", request.ctx.session.json)


@app.get("api/test/auth/associated")
@requires_authentication
async def on_get_associated_authentication_sessions(request):
    """Retrieves authentication sessions associated with logged in account."""
    authentication_sessions = await AuthenticationSession.get_associated(
        request.ctx.session.bearer
    )
    return json(
        "Associated authentication sessions retrieved!",
        [auth_session.json for auth_session in authentication_sessions],
    )


@app.get("api/test/capt/request")
async def on_captcha_request(request):
    """Request captcha with solution in response."""
    captcha_session = await CaptchaSession.new(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response)
    return response


@app.get("api/test/capt/image")
async def on_captcha_image(request):
    """Request captcha image."""
    captcha_session = await CaptchaSession.decode(request)
    return raw(captcha_session.get_image(), content_type="image/jpeg")


@app.get("api/test/capt/audio")
async def on_captcha_audio(request):
    """Request captcha audio."""
    captcha_session = await CaptchaSession.decode(request)
    return raw(captcha_session.get_audio(), content_type="audio/mpeg")


@app.post("api/test/capt")
@requires_captcha
async def on_captcha_attempt(request):
    """Attempt captcha challenge."""
    return json("Captcha attempt successful!", request.ctx.session.json)


@app.post("api/test/two-step/request")
async def on_request_verification(request):
    """Request two-step verification with code in the response."""
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response)
    return response


@app.post("api/test/two-step")
@requires_two_step_verification
async def on_verification_attempt(request):
    """Attempt two-step verification challenge."""
    return json("Two step verification attempt successful!", request.ctx.session.json)


@app.post("api/test/auth/roles")
async def on_authorization(request):
    """Check if client is authorized with sufficient roles and permissions."""
    await check_roles(request, request.form.get("role"))
    if request.form.get("permissions_required"):
        await check_permissions(
            request, *request.form.get("permissions_required").split(", ")
        )
    return text("Account permitted!")


@app.post("api/test/auth/roles/assign")
@requires_authentication
async def on_role_assign(request):
    """Assign authenticated account a role."""
    await assign_role(
        request.form.get("name"),
        request.ctx.session.bearer,
        "Role used for testing.",
        *(
            request.form.get("permissions").split(", ")
            if request.form.get("permissions")
            else []
        ),
    )
    return text("Role assigned!")


@app.post("api/test/account")
async def on_account_creation(request):
    """Quick account creation."""
    account = await Account.create(
        username=request.form.get("username"),
        email=request.form.get("email"),
        password=password_hasher.hash("password"),
        verified=True,
        disabled=False,
    )
    response = json("Account creation successful!", account.json)
    return response


@app.route("api/test/oauth", methods=["GET", "POST"])
async def on_oauth_request(request):
    """OAuth request."""
    return redirect(
        await google_oauth.get_authorization_url(
            "http://localhost:8000/api/test/oauth/callback",
            scope=google_oauth.base_scopes,
        )
    )


@app.get("api/test/oauth/callback")
async def on_oauth_callback(request):
    """OAuth callback."""
    token_info, authentication_session = await oauth_callback(
        request,
        google_oauth,
        "http://localhost:8000/api/test/oauth/callback",
    )
    response = json(
        "OAuth successful.",
        {"token_info": token_info, "auth_session": authentication_session.json},
    )
    oauth_encode(response, token_info)
    authentication_session.encode(response)
    return response


@app.get("api/test/oauth/token")
@requires_authentication
async def on_oauth_token(request):
    """OAuth token retrieval."""
    token_info = await oauth_decode(request, google_oauth)
    return json(
        "Access token retrieved!",
        {"token_info": token_info, "auth_session": request.ctx.session.json},
    )


@app.route("api/test/oauth/revoke", methods=["GET", "POST"])
async def on_oauth_revoke(request):
    """OAuth token revocation."""
    token_info = await oauth_revoke(request, google_oauth)
    return json("Access token revoked!", token_info)


@app.exception(SecurityError)
async def on_security_error(request, exception):
    """Handles security errors with correct response."""
    traceback.print_exc()
    return exception.json


config.SECRET = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU4vHCHEEZjdZIQRqwriFpeeoqMA1
ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStfVn25+ZfSfKH+WYBUglZBmz/K6uW
41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251QMHlkstd6FFYu5lJQcuppOm79iQI
DAQABAoIBAACRz1RBMmV9ruIFWtcNu24u1SBw8FAniW4SGuPBbxeg1KcmOlegx3IdkBhG7j9hBF5+S/3ZhGTGhYdglYcS2aSMK0Q6ofd4NDMk+bzlIdEZNTV
bTnlle1vBjVjxOoIP7aL6mC/HFO7T+SYqjIGkjsxYFHf1DFu0nHS5OA/rOoEt1SZA5DO0dCd1IjuPvKsvJIRErjnFuW6bs9K7XNpE2gHKvtvzVFRQC2F7AY7
b45cx6QZ08yCbToITRI59RzGgrpqIsJI0N5yT96DUALQDkAJz4XzhS8+bHoCDGeTPfJLq4xXcLrtFSk5Mhp4eIOPCI/fv3IO8JnSopgeP+y+NeFMCgYEA/rq
0R5v9JuxtcbXsFXua5KWoDojOvHkeP93F5eGSDu8iRo/4zhyHWGhZuMIuMARAOJ7tAyWxDTzoSILhC4+fF6WQJKiBIlLLGXFyJ9qgq2eN+Z/b9+k6PotQV9z
unmIN8vuCrtPBlVbOMrofGHG85zSDyDDDUXZoh7ko8tJ3nosCgYEAxAb/8E/fmEADxJZSFoqwlElXm6h7sfThrhjf12ENwBv7AvH8XsiNVQsIGnoVxeHQJ7U
0pROucD/iykf8I9+ou9ZBQyfoRJiOkzExeMWEyhmGyGmcNCZ1kKK/RZu6Bks/EoqnpVH9bUjjAwSXeFRZE3zfsAclQr3BYjqFjQzuSrsCgYEA7RhLBPwkPT6
C//wcqkJKgdfO/PhJtRPnG/sIYFf84vmiJZuMMgxLzfYSzO2wn/DU9d63LN7AVVoDurpXTbN4mUH5UKWmzJPThvMZFg9gzSmt9FLfI3lqRRzWw3FYiQMriKa
hlKh03tPVSVID73SuJ2Wx43u/0OstkGa/voQ34tECgYA+G2mjnerdtgp7kpTXh4GCueoD61GlhEyseD0TZDCTGUpiGIE5FpmQxDoBCYU0eOMWcZcIZj/yWIt
mQ4BjbU1slel/eXlhomQpxoBCH3J/Ba9qd+uBql29QZMQXtKFg/mryjprapq8sUcbgazr9u1x+zJz9w+bIbvPf3MoyVwGWQKBgQDXKMG9fV+/61imgsOZTyd
2ld8MnIWAeUGgk5e6P+niAOPGFSPue3FgGvLURiJtuu05dM9U9pQhtGVrCwHcT9Yixiwpnyw31DQp3uU91DhrtHyRIf3H/ywrWLwY4Z+TsktW6UPoe2cyGbN
1G1CHHo/vq8zPNkVWmhciIUeHR3YJbw==
-----END RSA PRIVATE KEY-----
"""
config.PUBLIC_SECRET = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU
4vHCHEEZjdZIQRqwriFpeeoqMA1ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStf
Vn25+ZfSfKH+WYBUglZBmz/K6uW41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251Q
MHlkstd6FFYu5lJQcuppOm79iQIDAQAB
-----END PUBLIC KEY-----
"""
config.INITIAL_ADMIN_EMAIL = "admin@login.test"
config.SESSION_ENCODING_ALGORITHM = "RS256"
config.ALLOW_LOGIN_WITH_USERNAME = True
config.SESSION_SECURE = False
register_tortoise(
    app,
    db_url=config.TEST_DATABASE_URL,
    modules={"models": ["sanic_security.models"]},
    generate_schemas=True,
)
initialize_security(app, True)
initialize_oauth(app)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
