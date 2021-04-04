from sanic import Sanic
from sanic.response import text, file
from tortoise.contrib.sanic import register_tortoise

from asyncauth.core.authentication import register, login, requires_authentication, \
    logout, request_account_recovery, account_recovery
from asyncauth.core.authorization import require_permissions, require_roles

from asyncauth.core.config import config
from asyncauth.core.middleware import xss_prevention, https_redirect
from asyncauth.core.models import AuthError, Permission, Role, VerificationSession, CaptchaSession
from asyncauth.core.verification import requires_captcha, request_captcha, requires_verification, verify_account, \
    request_verification
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
    await verification_session.text_code()
    response = json('Registration successful', verification_session.account.json())
    await verification_session.encode(response)
    return response


@app.post('api/test/register/verify')
@requires_verification()
async def on_verify(request, verification_session):
    """
    Attempt to verify account and allow access if unverified.
    """
    await verify_account(verification_session)
    return json('Verification successful!', verification_session.json())


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
    await captcha_session.encode(response)
    return response


@app.post('api/test/verification/resend')
async def resend_verification_request(request):
    """
    Resends verification code if somehow lost.
    """
    verification_session = await VerificationSession().decode(request)
    await verification_session.text_code()
    return json('Verification code resend successful', verification_session.json())


@app.post('api/test/verification/request')
async def new_verification_request(request):
    """
    Creates new verification code.
    """

    verification_session = await request_verification(request)
    await verification_session.text_code()
    response = json('Verification request successful', verification_session.json())
    await verification_session.encode(response)
    return response


@app.post('api/test/login')
async def on_login(request):
    """
    User login, creates and encodes authentication session.
    """
    authentication_session = await login(request)
    response = json('Login successful!', authentication_session.account.json())
    await authentication_session.encode(response)
    return response


@app.post('api/test/logout')
async def on_logout(request):
    """
    User logout, invalidates client authentication session.
    """
    authentication_session = await logout(request)
    response = json('Logout successful!', authentication_session.account.json())
    return response


@app.post('api/test/role/admin')
@requires_authentication()
async def on_create_admin(request, authentication_session):
    """
    Creates 'Admin' and 'Mod' roles to be used for testing role based authorization.
    """
    client = authentication_session.account
    await Role().create(account=client, name='Admin')
    await Role().create(account=client, name='Mod')
    return json('Roles added to your account!', client.json())


@app.post('api/test/perms/admin')
@requires_authentication()
async def on_create_admin_perm(request, authentication_session):
    """
    Creates 'admin:update' and 'admin:add' permissions to be used for testing wildcard based authorization.
    """
    client = authentication_session.account
    await Permission().create(account=client, wildcard='admin:update', decription="")
    await Permission().create(account=client, wildcard='admin:add')
    return json('Permissions added to your account!', client.json())


@app.get('api/test/client')
@requires_authentication()
async def on_test_client(request, authentication_session):
    """
    Retrieves authenticated client username.
    """
    return text('Hello ' + authentication_session.account.username + '!')


@app.get('api/test/perm')
@require_permissions('admin:update')
async def on_test_perm(request, authentication_session):
    """
    Tests client wildcard permissions authorization access.
    """
    return text('Admin who can only update gained access!')


@app.get('api/test/role')
@require_roles('Admin', 'Mod')
async def on_test_role(request, authentication_session):
    """
    Tests client role authorization access.
    """
    return text('Admin gained access!')


@app.get('api/test/recovery/request')
@requires_captcha()
async def on_recover_request(request):
    """
    Requests a recovery session to allow user to reset password with a code.
    """
    verification_session = await request_account_recovery(request)
    await verification_session.text_code()
    response = json('Recovery request successful', verification_session.json())
    await verification_session.encode(response)
    return response


@app.post('api/test/recovery')
@requires_verification()
async def on_recover(request, verification_session):
    """
    Changes and recovers an account's password.
    """
    await account_recovery(request, verification_session)
    return json('Account recovered successfully', verification_session.account.json())


@app.exception(AuthError)
async def on_error(request, exception):
    return json('An error has occurred!', {
        'error': type(exception).__name__,
        'summary': str(exception)
    }, status_code=exception.status_code)


if __name__ == '__main__':
    register_tortoise(app, db_url='mysql://admin:eG3FxzjAh9d1mdD63zky@personal.cbb4vtpozf6b.us-east-1.rds.amazonaws.com/amyrose',
                      modules={"models": ['asyncauth.core.models']}, generate_schemas=True)
    app.run(host='0.0.0.0', port=8000, debug=True)
