async def xss_middleware(request, response):
    response.headers['x-xss-protection'] = '1; mode=block'