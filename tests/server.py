from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

from argon2 import PasswordHasher
from sanic import Sanic, text
from tortoise.contrib.sanic import register_tortoise

from sanic_security import SanicSecurityExtension
from sanic_security.authentication import (
    login,
    register,
    requires_authentication,
    logout,
    create_initial_admin_account,
)
from sanic_security.authorization import (
    assign_role,
    check_permissions,
    check_roles,
)
from sanic_security.captcha import request_captcha, requires_captcha
from sanic_security.configuration import config as security_config
from sanic_security.exceptions import SecurityError, IntegrityError
from sanic_security.utils import json, get_image, encode
from sanic_security.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
)

"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2020-present Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


SECURITY_SECRET = """
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

PUBLIC_SECRET = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU
4vHCHEEZjdZIQRqwriFpeeoqMA1ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStf
Vn25+ZfSfKH+WYBUglZBmz/K6uW41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251Q
MHlkstd6FFYu5lJQcuppOm79iQIDAQAB
-----END PUBLIC KEY-----
"""


def make_app():
    app = Sanic("security-test")
    password_hasher = PasswordHasher()
    security = SanicSecurityExtension()

    ## umongo setup
    from mongomock_motor import AsyncMongoMockClient
    from umongo.frameworks import MotorAsyncIOInstance
    client = AsyncMongoMockClient("mongodb://mock:mock@127.0.0.1:27001/")
    client = client["mock_database"]
    lazy_umongo = MotorAsyncIOInstance()
    lazy_umongo.set_db(client)
    app.config.LAZY_UMONGO = lazy_umongo

    if app.config.get('SECURITY_ORM') == 'custom':
        from custom_orm import Role, Account, VerificationSession, TwoStepSession, CaptchaSession, AuthenticationSession
        security.init_app(app, account=Account, role=Role, 
                          verification=VerificationSession, twostep=TwoStepSession,
                          captcha=CaptchaSession, authentication=AuthenticationSession)
    else:
        security.init_app(app)

    _orm = Sanic.get_app().ctx.extensions['security']

    @app.post("api/test/auth/register")
    async def on_register(request):
        """
        Register an account with email and password.
        """
        account = await register(
            request.form,
            verified=request.form.get("verified") == "true",
            disabled=request.form.get("disabled") == "true",
        )
        if not account.verified:
            two_step_session = await request_two_step_verification(request, account)
            response = json(
                "Registration successful! Verification required.", two_step_session.code
            )
            encode(two_step_session, response)
        else:
            response = json("Registration successful!", await account.json())
        return response


    @app.post("api/test/auth/verify")
    async def on_verify(request):
        """
        Verifies an unverified account.
        """
        bearer = await verify_account(request)
        return json(
            "You have verified your account and may login!", await bearer.json()
        )


    @app.post("api/test/auth/login")
    async def on_login(request):
        """
        Login to an account with an email and password.
        """
        authentication_session = await login(request)
        response = json("Login successful!", await authentication_session.json())
        encode(authentication_session, response)
        return response


    @app.post("api/test/auth/logout")
    async def on_logout(request):
        """
        Logout of currently logged in account.
        """
        authentication_session = await logout(request)
        response = json("Logout successful!", await authentication_session.json())
        return response


    @app.post("api/test/auth")
    @requires_authentication()
    async def on_authenticate(request, authentication_session):
        """
        Check if current authentication session is valid.
        """
        response = json("Authenticated!", await authentication_session.json())
        encode(authentication_session, response)
        return response


    @app.get("api/test/capt/request")
    async def on_captcha_request(request):
        """
        Request captcha with solution in the response.
        """
        captcha_session = await request_captcha(request)
        response = json("Captcha request successful!", captcha_session.code)
        encode(captcha_session, response)
        return response


    @app.get("api/test/capt/image")
    async def on_captcha_image(request):
        """
        Request captcha image.
        """
        captcha_session = await _orm.captcha_session.decode(request)
        response = get_image()
        encode(captcha_session, response)
        return response


    @app.post("api/test/capt")
    @requires_captcha()
    async def on_captcha_attempt(request, captcha_session):
        """
        Attempt captcha.
        """
        return json("Captcha attempt successful!", await captcha_session.json())
        #return json("Captcha attempt successful!", captcha_session)


    @app.post("api/test/two-step/request")
    async def on_request_verification(request):
        """
        Request two-step verification with code in the response.
        """
        two_step_session = await request_two_step_verification(request)
        response = json("Verification request successful!", two_step_session.code)
        encode(two_step_session, response)
        return response


    @app.post("api/test/two-step")
    @requires_two_step_verification()
    async def on_verification_attempt(request, two_step_session):
        """
        Attempt two-step verification.
        """
        return json("Two step verification attempt successful!", await two_step_session.json())
        #return json("Two step verification attempt successful!", two_step_session)


    @app.post("api/test/auth/roles")
    @requires_authentication()
    async def on_authorization(request, authentication_session):
        """
        Check if client is authorized with sufficient roles and permissions.
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
        Assign authenticated account a role.
        """
        await assign_role(
            request.form.get("name"),
            authentication_session.bearer,
            request.form.get("permissions"),
            "Role used for testing.",
        )
        return text("Role assigned.")


    @app.post("api/test/account")
    async def on_account_creation(request):
        """
        Quick account creation.
        """
        try:
            username = "not_registered"
            if request.form.get("username"):
                username = request.form.get("username")
            account = await _orm.account.new(
                username=username,
                email=request.form.get("email"),
                password=password_hasher.hash("testtest"),
                verified=True,
                disabled=False,
                phone=request.form.get("phone")
            )
            response = json("Account creation successful!", await account.json())
        except IntegrityError:
            response = json("Account with these credentials already exist!", None)
        return response


    @app.exception(SecurityError)
    async def on_error(request, exception):
        return exception.json_response

    security_config.SANIC_SECURITY_SECRET = SECURITY_SECRET
    security_config.SANIC_SECURITY_PUBLIC_SECRET = PUBLIC_SECRET
    security_config.SANIC_SECURITY_SESSION_ENCODING_ALGORITHM = "RS256"
    security_config.SANIC_SECURITY_ALLOW_LOGIN_WITH_USERNAME = True
    security_config.SANIC_SECURITY_SESSION_SECURE = False

    register_tortoise(
        app,
        db_url=security_config.SANIC_SECURITY_TEST_DATABASE_URL,
        modules={"models": ["sanic_security.orm.tortoise"]},
        generate_schemas=True,
    )


    create_initial_admin_account(app)

    return app

if __name__ == "__main__":
    _app = make_app()
    _app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
