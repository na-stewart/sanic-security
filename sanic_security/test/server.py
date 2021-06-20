from sanic import Sanic

from sanic_security.authentication import register, login
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.utils import json
from sanic_security.verification import verify_account, two_step_verification

app = Sanic("test")


@app.post("api/test/auth/register")
async def on_register(request):
    two_step_session = await register(request)
    response = json("Registration successful!", two_step_session.code)
    two_step_session.encode(response, secure=False)
    return response


@app.post("api/test/auth/verify")
async def on_verify(request):

    two_step_session = await two_step_verification(request)
    await verify_account(two_step_session)
    return json("Account verification successful!", two_step_session.account.json())


@app.post("api/test/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.json())
    authentication_session.encode(response, secure=False)
    return response


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
