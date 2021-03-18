from sanic.response import redirect


def xss_prevention(request, response):
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect(request, debug=False):
    if request.url.startswith('http://') and not debug:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)
