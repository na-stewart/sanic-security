from amyrose.core.authentication import authenticate
from amyrose.core.authorization import authorize


async def xss_middleware(request, response):
    response.headers['x-xss-protection'] = '1; mode=block'