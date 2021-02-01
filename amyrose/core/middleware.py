from sanic.response import redirect


def xss_middleware(request, response):
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect(request):
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)
