from sanic import Sanic
from sanic.response import text, json

from amyrose.core.authentication import register, login, verify_account, requires_authentication, get_client, logout
from amyrose.core.authorization import requires_permission, requires_role
from amyrose.core.management import create_permission, create_role
from amyrose.core.middleware import xss_middleware
from amyrose.core.utils import text_verification_code
from amyrose.lib.tortoise import tortoise_init

app = Sanic('AmyRose tests')


@app.middleware('response')
async def response_middleware(request, response):
    await xss_middleware(request, response)


@app.post('/register')
async def on_register(request):
    account, verification_session = await register(request)
    await text_verification_code(account, verification_session)
    response = text('Registration successful')
    response.cookies[verification_session.cookie_name()] = verification_session.to_cookie()
    return response


@app.post('/login')
async def on_login(request):
    account, authentication_session = await login(request)
    response = text('Login successful')
    response.cookies[authentication_session.cookie_name()] = authentication_session.to_cookie()
    return response


@app.post('/logout')
async def on_logout(request):
    account, authentication_session = await logout(request)
    response = text('Logout successful')
    del response.cookies[authentication_session.cookie_name()]
    return response


@app.post('/verify')
async def on_verify(request):
    account, verification_session = await verify_account(request)
    return text('Verification successful')


@app.get("/test")
@requires_authentication()
async def test(request):
    return text('Hello auth world!')


@app.post('/createadmin')
async def on_create_admin(request):
    client = await get_client(request)
    await create_role(client, 'Admin')
    return text('Hello Admin!')


@app.post('/createadminperm')
async def on_create_admin_perm(request):
    client = await get_client(request)
    await create_permission(client, 'admin:update')
    return text('Hello Admin who can only update!')


@app.get('/testclient')
async def on_test_client(request):
    client = await get_client(request)
    return text('Hello ' + client.username + '!')


@app.get('/testperm')
@requires_permission('admin:update')
async def on_test_perm(request):
    return text('Admin who can only update gained access!')


@app.get('/testrole')
@requires_role('Admin')
async def on_test_role(request):
    return text('Admin gained access!')


if __name__ == '__main__':
    app.add_task(tortoise_init())
    app.run(host='0.0.0.0', port=8000, debug=True)
