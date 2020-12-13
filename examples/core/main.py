from sanic import Sanic
from amyrose.core.authentication import register, login, verify_account, requires_authentication, get_client, logout
from amyrose.core.authorization import requires_role
from amyrose.core.middleware import xss_middleware
from amyrose.core.utils import text_verification_code
from amyrose.lib.tortoise import tortoise_init
from examples.core.models import ForumEntry, base_response

app = Sanic('Amy Rose Forum Site Api Example')


@app.middleware('response')
async def response_middleware(request, response):
    await xss_middleware(request, response)


@app.post('/register')
async def on_register(request):
    account, verification_session = await register(request)
    await text_verification_code(account, verification_session)
    content = {'Username': account.username, 'Email': account.email, 'Phone': account.phone,
               'Verified': account.verified}
    response = base_response('Registration successful, please verify your account', content)
    response.cookies[verification_session.cookie_name()] = verification_session.encode()
    return response


@app.post('/login')
async def on_login(request):
    account, authentication_session = await login(request)
    cookie = authentication_session.encode()
    content = {'Username': account.username, 'Email': account.email, 'Token': cookie}
    response = base_response('Login successful!', content)
    response.cookies[authentication_session.cookie_name()] = cookie
    return response


@app.post('/verify')
async def on_verify(request):
    account, verification_session = await verify_account(request)
    content = {'Username': account.username, 'Verified': account.verified}
    return base_response('Verification Successful!', content)


@app.post('/submitentry')
@requires_authentication()
async def submit_forum_entry(request):
    params = request.form
    client = await get_client(request)
    entry = await ForumEntry().create(parent_name=client.username, title=params.get('title'),
                                      content=params.get('content'))
    content = {'author': entry.parent_name, 'title': entry.title, 'content': entry.content}
    return base_response('Forum entry submitted!', content)


@app.post('/logout')
async def on_logout(request):
    account, authentication_session = await logout(request)
    return base_response('Logout successful!', None)


@app.get('/getforums')
async def get_all_forum_entries(request):
    entries = await ForumEntry().all()
    content = []
    for entry in entries:
        content.append({
            'author': entry.parent_name,
            'title': entry.title,
            'content': entry.content
        })
    return base_response('Entries retrieved!', content)


@app.get('/deleteentry')
@requires_role('Admin')
async def get_all_forum_entries(request):
    params = request.form
    entry = await ForumEntry().filter(title=params.get('title')).first()
    entry.deleted = True
    await entry.save(update_fields=['deleted'])
    return base_response('Entry has been successfully deleted!', None)


if __name__ == '__main__':
    app.add_task(tortoise_init())
    app.run(host='0.0.0.0', debug=True, port=8000)
