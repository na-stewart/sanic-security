from sanic import Sanic
from sanic.response import text

from amyrose.core.authentication import register, login, verify_account, requires_authentication, get_client
from amyrose.core.authorization import requires_role, create_role, create_permission, requires_permission
from amyrose.core.middleware import xss_middleware, auth_middleware
from amyrose.core.utils import send_verification_code
from amyrose.lib.tortoise import tortoise_init

app = Sanic('AmyRose example')


@app.middleware('request')
async def request_middleware(request):
    await auth_middleware(request)


@app.middleware('response')
async def response_middleware(request, response):
    await xss_middleware(request, response)


@app.post('/register')
async def on_register(request):
    account, session = await register(request)
    await send_verification_code(account, session)
    response = text('Registration successful')
    response.cookies[session.cookie_name] = session.to_cookie()
    return response


@app.post('/login')
async def on_login(request):
    account, session = await login(request)
    response = text('Login successful')
    response.cookies[session.cookie_name] = session.to_cookie()
    return response


@app.post('/verify')
async def on_verify(request):
    await verify_account(request)
    return text('Verification successful')


@requires_authentication('/test')
@app.get('/test')
async def on_test_auth(request):
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


@requires_permission('/testperm', 'admin:update')
@app.get('/testperm')
async def on_test_perm(request):
    return text('Admin who can only update gained access!')


@requires_role('/testrole', 'Admin')
@app.get('/testrole')
async def on_test_role(request):
    return text('Admin gained access!')


if __name__ == '__main__':
    app.add_task(tortoise_init())
    app.run(host='0.0.0.0', port=8000)
