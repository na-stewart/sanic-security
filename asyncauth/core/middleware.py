import asyncio

from sanic import Request
from sanic.response import redirect, HTTPResponse

from asyncauth.core.config import config
from asyncauth.core.utils import get_ip
from asyncauth.lib.ip2proxy import ip2proxy_crosscheck


def ip_validation(request: Request):
    """
    Checks to see if ip address is a proxy.
    """
    if config['AUTH']['debug'] == 'false':
        loop = asyncio.get_event_loop()
        ip = get_ip(request)
        loop.run_in_executor(None, ip2proxy_crosscheck, ip)


def xss_prevention(request: Request, response: HTTPResponse):
    """
    Adds a header to all responses to prevent cross site scripting.
    """
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect(request: Request):
    """
    :param request: Sanic request parameter.

    :return: redirect_url
    """
    if request.url.startswith('http://') and config['AUTH']['debug'] == 'false':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)
