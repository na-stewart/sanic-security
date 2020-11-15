from sanic import Sanic
from amyrose.core.authentication import register, login, verify_account
from amyrose.core.middleware import xss_middleware, auth_middleware
from amyrose.core.utils import text_verification_code
from amyrose.lib.tortoise import tortoise_init
from examples.Forum.core.models import BaseResponse

app = Sanic('AmyRose tests')


@app.middleware('request')
async def request_middleware(request):
    await auth_middleware(request)


@app.middleware('response')
async def response_middleware(request, response):
    await xss_middleware(request, response)


@app.post('/register')
async def on_register(request):
    account, verification_session = await register(request)
    await text_verification_code(account, verification_session)
    content = {'Username': account.username, 'Email': account.email, 'Phone': account.phone}
    response = BaseResponse('Registration successful, please verify your account', content)
    response.cookies[verification_session.cookie_name] = verification_session.to_cookie()
    return response


@app.post('/login')
async def on_login(request):
    account, authentication_session = await login(request)
    content = {'Username': account.username, 'Token': authentication_session.to_cookie()}
    response = BaseResponse('Login successful.', content)
    response.cookies[authentication_session.cookie_name] = authentication_session.to_cookie()
    return response


@app.post('/verify')
async def on_verify(request):
    account, verification_session = await verify_account(request)
    content = {'Username': account.username, 'Verified': account.verified}
    return BaseResponse('Verification Successful', content)


if __name__ == '__main__':
    app.add_task(tortoise_init())
    app.run(host='0.0.0.0', port=8000)
