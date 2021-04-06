import os

from sanic.request import Request
from sanic_ipware import get_client_ip

from asyncauth.core.config import config


def get_ip(request: Request):
    """
    Retrieves the ip address of the request.

    :param request: Sanic request.
    """
    proxies = config['AUTH']['proxies'].split(',').strip() if config.has_option('AUTH', 'proxies') else None
    ip, routable = get_client_ip(request, proxy_trusted_ips=proxies, proxy_count=len(proxies) if proxies else 0)
    return ip if ip is not None else '0.0.0.0'


def path_exists(path):
    """
    Checks if path exists, and creates it if it doesn't.

    :param path: Path being checked.

    :return: exists
    """
    exists = os.path.exists(path)
    if not exists:
        os.makedirs(path)
    return exists
