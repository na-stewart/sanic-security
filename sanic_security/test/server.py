from sanic import Sanic
from sanic.exceptions import ServerError
from sanic.response import json as sanic_json
from sanic.response import text, file

from sanic_security.core.authentication import register, login, requires_authentication, logout
from sanic_security.core.authorization import require_permissions, require_roles
from sanic_security.core.initializer import initialize_security
from sanic_security.core.models import SecurityError, Permission, Role, VerificationSession, CaptchaSession
from sanic_security.core.recovery import attempt_recovery, fulfill_recovery_attempt
from sanic_security.core.utils import xss_prevention_middleware
from sanic_security.core.verification import requires_captcha, request_captcha, requires_verification, verify_account, \
    request_verification
from sanic_security.lib.ip2proxy import detect_proxy

app = Sanic('Sanic Security test server')


def json(message, content, status_code=200):
    payload = {
        'message': message,
        'status_code': status_code,
        'content': content
    }
    return sanic_json(payload, status=status_code)


def check_for_empty(form, *args):
    for key, value in form.items():
        if value is not None:
            if not isinstance(value[0], bool) and not value[0] and key not in args:
                raise ServerError(key + " is empty!", 400)


@app.middleware('response')
async def xxs_middleware(request, response):
    """
    Response middleware test.
    """
    xss_prevention_middleware(request, response)


@app.post('api/test/register')
async def on_register(request):
    """
    Registration test without verification or captcha requirements.
    """
    account = await register(request, verified=True)
    return json('Registration Successful!', account.json())


@app.post('api/test/register/verification')
@requires_captcha()
async def on_register_verification(request, captcha_session):
    """
    Registration test with all built-in requirements.
    """
    verification_session = await register(request)
    await verification_session.text_code()
    response = json('Registration successful', verification_session.account.json())
    verification_session.encode(response, secure=False)
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
    img_path = await CaptchaSession.captcha_img(request)
    return await file(img_path)


@app.get('api/test/captcha')
async def on_request_captcha(request):
    """
    Requests captcha session for client.
    """
    captcha_session = await request_captcha(request)
    response = json('Captcha request successful!', captcha_session.json())
    captcha_session.encode(response, secure=False)
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
    verification_session.encode(response, secure=False)
    return response


@app.post('api/test/login')
async def on_login(request):
    """
    User login, creates and encodes authentication session.
    """
    authentication_session = await login(request)
    response = json('Login successful!', authentication_session.account.json())
    authentication_session.encode(response, secure=False)
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
@detect_proxy()
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


@app.post('api/test/recovery/attempt')
@requires_captcha()
async def on_recovery_attempt(request, captcha_session):
    """
    Attempts to recover account via changing password, requests verification to ensure the recovery attempt was made
    by account owner.
    """
    verification_session = await attempt_recovery(request)
    await verification_session.text_code()
    response = json('A recovery attempt has been made, please verify account ownership.', verification_session.json())
    verification_session.encode(response, secure=False)
    return response


@app.post('api/test/recovery/fulfill')
@requires_verification()
async def on_recovery_fulfill(request, verification_session):
    """
    Changes and recovers an account's password once recovery attempt was determined to have been made by account owner.
    """
    await fulfill_recovery_attempt(request, verification_session)
    return json('Account recovered successfully', verification_session.account.json())


@app.exception(SecurityError)
async def on_error(request, exception):
    return json('An error has occurred!', {
        'error': type(exception).__name__,
        'summary': str(exception)
    }, status_code=exception.status_code)


if __name__ == '__main__':
    initialize_security(app)
    app.run(host='0.0.0.0', port=8000, debug=True, workers=4)
