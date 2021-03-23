from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import text, file

from asyncauth.core.authentication import register, login, requires_authentication, \
    logout, request_recovery, recover
from asyncauth.core.authorization import require_permissions, require_roles
from asyncauth.core.initializer import initialize_auth
from asyncauth.core.middleware import xss_prevention, https_redirect
from asyncauth.core.models import RoseError, CaptchaSession, Account, Role, Permission, VerificationSession
from asyncauth.core.utils import text_verification_code
from asyncauth.core.verification import verify_account, requires_captcha, request_captcha
from test.models import json

app = Sanic('asyncauth Postman Tests')


@app.middleware('response')
async def response_middleware(request, response):
    xss_prevention(request, response)


@app.middleware('request')
async def request_middleware(request):
    return https_redirect(request, True)


# AUTHENTICATION

@app.post('api/test/register')
# Tests registration without requiring captcha or verification.
async def on_register(request):
    account = await register(request, verified=True)
    return json('Registration Successful!', account.json())


@app.post('api/test/register/verification')
@requires_captcha()
async def on_register(request):
    verification_session = await register(request)
    await text_verification_code(verification_session.account.phone, verification_session.code)
    response = text('Registration successful', verification_session.account.json())
    verification_session.encode(response)
    return response


@app.get('api/test/captcha/img')
async def on_captcha_img(request):
    img_path = await CaptchaSession().captcha_img(request)
    return await file(img_path)


@app.get('api/test/captcha')
async def on_request_captcha(request):
    captcha_session = await request_captcha(request)
    response = json('Captcha request successful!', captcha_session.json())
    captcha_session.encode(response)
    return response


@app.post('api/test/verification/resend')
async def resend_verification_request(request):
    verification_session = await VerificationSession().decode(request)
    VerificationSession.ErrorFactory(verification_session).throw()
    await text_verification_code(verification_session.account.phone, verification_session.code)
    return json('Verification code resend successful', verification_session.json())


@app.post('api/test/login')
async def on_login(request):
    authentication_session = await login(request)
    response = text('Login successful')
    authentication_session.encode(response)
    return response


@app.post('api/test/logout')
async def on_logout(request):
    await logout(request)
    response = text('Logout successful')
    return response


@app.post('api/test/verify')
async def on_verify(request):
    verification_session = await verify_account(request)
    return text('Verification successful')


@app.get("api/test")
@requires_authentication()
async def test(request):
    return text('Hello auth world!')


@app.post('api/test/role/admin')
async def on_create_admin(request):
    client = await Account.get_client(request)
    await Role().create(account=client, name='Admin')
    await Role().create(account=client, name='Mod')
    return json('Roles added to your account!', client.json())


@app.post('api/test/perms/admin')
async def on_create_admin_perm(request):
    client = await Account().get_client(request)
    await Permission().create(account=client, wildcard='admin:update', decription="")
    await Permission().create(account=client, wildcard='admin:add')
    return json('Permissions added to your account!', client.json())


@app.get('api/test/client')
async def on_test_client(request):
    client = await Account().get_client(request)
    return text('Hello ' + client.username + '!')


@app.get('api/test/perm')
@require_permissions('admin:update')
async def on_test_perm(request):
    return text('Admin who can only update gained access!')


@app.get('api/test/role')
@require_roles('Admin', 'Mod')
async def on_test_role(request):
    return text('Admin gained access!')


@app.post('api/test/recovery')
async def on_recover_request(request):
    recovery_session = await request_recovery(request)
    await text_verification_code(recovery_session.account.phone, recovery_session.code)
    response = json('Recovery request successful', recovery_session.json())
    recovery_session.encode(response)
    return response


@app.post('api/test/recover')
async def on_recover(request):
    recovery_session = await recover(request)
    return json('Account recovered successfully', recovery_session.account.json())


if __name__ == '__main__':
    initialize_auth(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
