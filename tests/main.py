from sanic import Sanic
from sanic.response import text

from amyrose.core.authentication import register, verify_account, authentication_middleware, login, \
    prevent_xss_middleware
from amyrose.core.utils import send_verification_code
from amyrose.lib.tortoise import tortoise_init

app = Sanic("AmyRose example")


@app.middleware('request')
async def auth_middleware(request):
    await authentication_middleware(request)


@app.middleware('response')
async def xxs_middleware(request, response):
    await prevent_xss_middleware(request, response)


@app.post("/register")
async def on_register(request):
    account, session = await register(request)
    await send_verification_code(account, session)
    response = text('Registration successful')
    response.cookies[session.token_name] = session.token
    return response


@app.post("/login")
async def on_login(request):
    account, session = await login(request)
    response = text('Login successful')
    response.cookies[session.token_name] = session.token
    return response


@app.post("/verify")
async def on_verify(request):
    await verify_account(request)
    return text('Verification successful')


@app.get("/test")
async def on_verify(request):
    return text('Test successful')


if __name__ == "__main__":
    app.add_task(tortoise_init())
    app.run(host="0.0.0.0", port=8000)
