from sanic.exceptions import ServerError

from amyrose.core.authentication import authenticate
from amyrose.core.authorization import endpoints_requiring_role, authorize


async def xss_middleware(request, response):
    response.headers['x-xss-protection'] = '1; mode=block'


async def auth_middleware(request):
    authentication_session = await authenticate(request)
    #await authorize(authentication_session, role=endpoints_requiring_role[request.endpoint])
