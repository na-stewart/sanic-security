import hashlib
import os

from sanic.request import Request
from sanic.response import HTTPResponse, redirect
from sanic_ipware import get_client_ip

from asyncauth.core.config import config


def xss_prevention_middleware(request: Request, response: HTTPResponse):
    """
    Adds a header to all responses to prevent cross site scripting.
    """
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect_middleware(request: Request):
    """
    :param request: Sanic request parameter.

    :return: redirect_url
    """
    if request.url.startswith('http://') and config['AUTH']['debug'] == 'false':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)


def hash_pw(password: str):
    """
    Turns passed text into hashed password
    :param password: Password to be hashed.
    :return: hashed
    """
    return hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), config['AUTH']['SECRET'].encode('utf-8'), 100000)


def get_ip(request: Request):
    return request.remote_addr if request.ip == '127.0.0.1' else request.ip


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
