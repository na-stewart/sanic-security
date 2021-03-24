from sanic.response import redirect


def xss_prevention(request, response):
    """
    Adds a header to all responses to prevent cross site scripting.
    """
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect(request, debug=False):
    """
    :param request: Sanic request parameter.
    :param debug: This middleware will redirect all requests to https unless debug is True.
    :return: redirect_url
    """
    if request.url.startswith('http://') and not debug:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)
