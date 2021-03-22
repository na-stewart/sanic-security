from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import text, json, file

from asyncauth.core.authentication import register, login, requires_authentication, \
    logout, request_recovery, recover
from asyncauth.core.authorization import require_permissions, require_roles
from asyncauth.core.initializer import initialize_auth
from asyncauth.core.middleware import xss_prevention
from asyncauth.core.models import RoseError, CaptchaSession, Account, Role, Permission, VerificationSession
from asyncauth.core.utils import text_verification_code
from asyncauth.core.verification import verify_account, requires_captcha, request_captcha

app = Sanic('AmyRose tests')


@app.middleware('response')
async def response_middleware(request, response):
    xss_prevention(request, response)


@app.post('/register')
async def on_register(request):
    account = await register(request, verified=True)
    response = text('Registration successful')
    return response


@app.post('/register/verification')
@requires_captcha()
async def on_register(request):
    verification_session = await register(request)
    await text_verification_code(verification_session.account.phone, verification_session.code)
    response = text('Registration successful')
    verification_session.encode(response)
    return response


@app.post('/recovery')
async def on_recover_request(request):
    recovery_session = await request_recovery(request)
    await text_verification_code(recovery_session.account.phone, recovery_session.code)
    response = text('Recovery request successful')
    recovery_session.encode(response)
    return response


@app.post('/recover')
async def on_recover(request):
    recovery_session = await recover(request)
    return text('Account has been recovered successfully!')


@app.get('/captcha/img')
async def on_captcha_img(request):
    img_path = await CaptchaSession().captcha_img(request)
    response = await file(img_path)
    return response


@app.get('/captcha')
async def on_request_captcha(request):
    captcha_session = await request_captcha(request)
    response = text('Captcha request successful!')
    captcha_session.encode(response)
    return response


@app.post('/resend')
async def resend_verification_request(request):
    verification_session = await VerificationSession().decode(request)
    VerificationSession.ErrorFactory(verification_session).throw()
    await text_verification_code(verification_session.account.phone, verification_session.code)
    response = text('Resend request successful.')
    return response


@app.post('/login')
async def on_login(request):
    authentication_session = await login(request)
    response = text('Login successful')
    authentication_session.encode(response)
    return response


@app.post('/logout')
async def on_logout(request):
    await logout(request)
    response = text('Logout successful')
    return response


@app.post('/verify')
async def on_verify(request):
    verification_session = await verify_account(request)
    return text('Verification successful')


@app.get("/test")
@requires_authentication()
async def test(request):
    return text('Hello auth world!')


@app.post('/createadmin')
async def on_create_admin(request):
    client = await Account.get_client(request)
    await Role().create(account=client, name='Admin')
    await Role().create(account=client, name='Mod')
    return text('Hello Admin!')


@app.post('/createadminperms')
async def on_create_admin_perm(request):
    client = await Account().get_client(request)
    await Permission().create(account=client, wildcard='admin:update', decription="")
    await Permission().create(account=client, wildcard='admin:add')
    return text('Hello Admin who can only update and add!')


@app.get('/testclient')
async def on_test_client(request):
    client = await Account().get_client(request)
    return text('Hello ' + client.username + '!')


@app.get('/testperm')
@require_permissions('admin:update')
async def on_test_perm(request):
    return text('Admin who can only update gained access!')


@app.get('/testjson')
async def on_test_json(request):
    client = await Account().get_client(request)
    return json(client.json(), 200)


@app.get('/testrole')
@require_roles('Admin', 'Mod')
async def on_test_role(request):
    return text('Admin gained access!')


@app.exception(RoseError)
async def on_rose_error_test(request, exception: ServerError):
    payload = {
        'error': str(exception),
        'status': exception.status_code
    }
    return json(payload, status=exception.status_code)


if __name__ == '__main__':
    initialize_auth(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
