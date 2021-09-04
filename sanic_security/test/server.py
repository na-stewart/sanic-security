from sanic import Sanic
from tortoise.exceptions import IntegrityError

from sanic_security.authentication import login, validate_second_factor, register
from sanic_security.blueprints import security
from sanic_security.exceptions import SecurityError, UnverifiedError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.models import Account
from sanic_security.utils import json, hash_password
from sanic_security.verification import request_two_step_verification, requires_two_step_verification, verify_account

app = Sanic(__name__)


@app.post("api/auth/register")
async def on_register(request, captcha_session):
    account = await register(request, verified=request.form.get("verified") == "true",
                             disabled=request.form.get("disabled") == "true")
    two_step_session = await request_two_step_verification(request, account)
    await two_step_session.email_code()
    response = json("Registration successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response


@app.post("api/test/auth/login/two-factor")
async def on_login_with_two_factor_authentication(request):
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(request, authentication_session.account)
    await two_step_session.email_code()
    response = json("Login successful! A second factor is now required to be authenticated.",
                    authentication_session.account.json())
    authentication_session.encode(response, False)
    two_step_session.encode(response, False)
    return response


@app.post("api/test/auth/login/second-factor")
@requires_two_step_verification()
async def on_second_factor(request, two_step_verification):
    authentication_session = await validate_second_factor(request)
    response = json("Second factor attempt successful!", authentication_session.account.json())
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json("You have verified your account and may login!", two_step_session.account.json())


@app.post("api/test/auth/login/unverified")
async def on_login_with_verification_check(request):
    account = await Account.get_via_email(request.form.get("email"))
    try:
        authentication_session = await login(request, account)
    except UnverifiedError as e:
        two_step_session = await request_two_step_verification(request, account)
        await two_step_session.email_code()
        two_step_session.encode(e.response, False)
        return e.response
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response, False)
    return response


@app.post("api/test/account/create")
async def on_account_creation(request):
    """
    Creates an account to be used for testing purposes.
    """
    try:
        account = await Account.create(
            username="test",
            email=request.form.get("email"),
            password=hash_password("password"),
            verified=request.form.get("verified") == "true",
            disabled=request.form.get("disabled") == "true",
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
