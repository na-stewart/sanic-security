import os

from sanic.request import Request
from sanic_ipware import get_client_ip

from asyncauth.core.config import config
from asyncauth.core.models import ForbiddenConnectionError


def get_ip(request: Request):
    """
    Retrieves the ip address of the request.

    :param request: Sanic request.
    """
    proxies = config['AUTH']['proxies'].split(',').strip() if config.has_option('AUTH', 'proxies') else None
    proxy_count = int(config['AUTH']['proxy_count']) if config.has_option('AUTH', 'proxy_count') else None
    proxy_order = config['AUTH']['proxy_order']
    ip, routable = get_client_ip(request, proxy_trusted_ips=proxies, proxy_count=proxy_count, proxy_order=proxy_order)
    if ip is None:
        if config['AUTH']['debug'] == 'true':
            raise ForbiddenConnectionError('No ')
    return ip if ip else '0.0.0.0'


def path_exists(path):
    """
    Checks if path exists and isn't empty, and creates it if it doesn't.

    :param path: Path being checked.

    :return: exists
    """
    exists = os.path.exists(path)
    if not exists:
        os.makedirs(path)
    return exists and os.listdir(path)
