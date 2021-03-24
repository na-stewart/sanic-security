from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import text, file

from asyncauth.core.authentication import register, login, requires_authentication, \
    logout, request_recovery, recover
from asyncauth.core.authorization import require_permissions, require_roles
from asyncauth.core.initializer import initialize_auth
from asyncauth.core.middleware import xss_prevention, https_redirect
from asyncauth.core.models import CaptchaSession, Account, Role, Permission, VerificationSession
from asyncauth.core.utils import text_verification_code
from asyncauth.core.verification import verify_account, requires_captcha, request_captcha
from asyncauth.test.models import json

app = Sanic('asyncauth Postman Test')


@app.middleware('response')
async def response_middleware(request, response):
    """
    Response middleware test.
    """
    xss_prevention(request, response)


@app.middleware('request')
async def request_middleware(request):
    """
    Request middleware test.
    """
    return https_redirect(request, True)


@app.post('api/test/register')
async def on_register(request):
    """
    Registration test without verification or captcha requirements.
    """
    account = await register(request, verified=True)
    return json('Registration Successful!', account.json())


@app.post('api/test/register/verification')
@requires_captcha()
async def on_register_verification(request):
    """
    Registration test with all built-in requirements.
    """
    verification_session = await register(request)
    await text_verification_code(verification_session.account.phone, verification_session.code)
    response = text('Registration successful', verification_session.account.json())
    verification_session.encode(response)
    return response


@app.get('api/test/captcha/img')
async def on_captcha_img(request):
    """
    Retrieves captcha image from captcha session.
    """
    img_path = await CaptchaSession().captcha_img(request)
    return await file(img_path)


@app.get('api/test/captcha')
async def on_request_captcha(request):
    """
    Requests captcha session for client.
    """
    captcha_session = await request_captcha(request)
    response = json('Captcha request successful!', captcha_session.json())
    captcha_session.encode(response)
    return response


@app.post('api/test/verification/resend')
async def resend_verification_request(request):
    """
    Resends verification code if somehow lost.
    """
    verification_session = await VerificationSession().decode(request)
    VerificationSession.ErrorFactory(verification_session).throw()
    await text_verification_code(verification_session.account.phone, verification_session.code)
    return json('Verification code resend successful', verification_session.json())


@app.post('api/test/login')
async def on_login(request):
    """
    User login, creates and encodes authentication session.
    """
    authentication_session = await login(request)
    response = json('Login successful!', authentication_session.account.json())
    authentication_session.encode(response)
    return response


@app.post('api/test/logout')
async def on_logout(request):
    """
    User logout, invalidates client authentication session.
    """
    await logout(request)
    response = text('Logout successful!')
    return response


@app.post('api/test/verify')
async def on_verify(request):
    """
    Attempt to verify account and allow access if unverified.
    """
    verification_session = await verify_account(request)
    return json('Verification successful!', verification_session.json())


@app.post('api/test/role/admin')
async def on_create_admin(request):
    """
    Creates 'Admin' and 'Mod' roles to be used for testing role based authorization.
    """
    client = await Account.get_client(request)
    await Role().create(account=client, name='Admin')
    await Role().create(account=client, name='Mod')
    return json('Roles added to your account!', client.json())


@app.post('api/test/perms/admin')
async def on_create_admin_perm(request):
    """
    Creates 'admin:update' and 'admin:add' permissions to be used for testing wildcard based authorization.
    """
    client = await Account().get_client(request)
    await Permission().create(account=client, wildcard='admin:update', decription="")
    await Permission().create(account=client, wildcard='admin:add')
    return json('Permissions added to your account!', client.json())


@app.get('api/test/client')
@requires_authentication()
async def on_test_client(request):
    """
    Retrieves authenticated client username.
    """
    client = await Account().get_client(request)
    return text('Hello ' + client.username + '!')


@app.get('api/test/perm')
@require_permissions('admin:update')
async def on_test_perm(request):
    """
    Tests client wildcard permissions authorization access.
    """
    return text('Admin who can only update gained access!')


@app.get('api/test/role')
@require_roles('Admin', 'Mod')
async def on_test_role(request):
    """
    Tests client role authorization access.
    """
    return text('Admin gained access!')


@app.post('api/test/recovery')
async def on_recover_request(request):
    """
    Requests a recovery session to allow user to reset password with a code.
    """
    recovery_session = await request_recovery(request)
    await text_verification_code(recovery_session.account.phone, recovery_session.code)
    response = json('Recovery request successful', recovery_session.json())
    recovery_session.encode(response)
    return response


@app.post('api/test/recover')
async def on_recover(request):
    """
    Changes and recovers an account's password is code is correct and session is valid.
    """
    recovery_session = await recover(request)
    return json('Account recovered successfully', recovery_session.account.json())


@app.exception(ServerError)
async def on_error(request, exception):
    return json('An error has occurred!', {
        'error': type(exception).__name__,
        'summary': str(exception)
    }, status_code=exception.status_code)


if __name__ == '__main__':
    initialize_auth(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
