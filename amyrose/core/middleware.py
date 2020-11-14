from amyrose.core.authentication import authenticate
from amyrose.core.authorization import authorize


async def xss_middleware(request, response):
    response.headers['X-Xss-Protection'] = '1; mode=block'


async def auth_middleware(request):
    authentication_session = await authenticate(request)
    await authorize(request, authentication_session)
    request.headers['X-Client-Uid'] = authentication_session.parent_uid
