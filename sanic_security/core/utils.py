import hashlib
import os

from sanic.request import Request
from sanic.response import HTTPResponse, redirect

from sanic_security.core.config import config


def xss_prevention_middleware(request: Request, response: HTTPResponse):
    """
    Adds a header to all responses that prevents cross site scripting.

    :param request: Sanic request parameter.

    :param response: Sanic http response parameter.
    """
    response.headers['x-xss-protection'] = '1; mode=block'


def https_redirect_middleware(request: Request):
    """
    Redirects all http requests to https.

    :param request: Sanic request parameter.

    :return: redirect_url
    """
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)


def hash_pw(password: str):
    """
    Turns passed text into hashed password

    :param password: Password to be hashed.

    :return: hashed_password
    """
    return hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), config['AUTH']['SECRET'].encode('utf-8'), 100000)


def get_ip(request: Request):
    """
    Retrieves ip address from request.

    :param request: Sanic request parameter.

    :return: ip
    """
    return request.remote_addr if request.remote_addr else request.ip


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
