import hashlib
import os
from configparser import ConfigParser
from sanic.request import Request
from sanic.response import HTTPResponse, redirect
from sanic.response import json as sanic_json

security_cache_path = "./resources/security-cache"
config = ConfigParser()
config.read("./security.ini")


def xss_prevention_middleware(request: Request, response: HTTPResponse):
    """
    Adds a header to all responses that prevents cross site scripting.

    Args:
        request: (Request): Sanic request parameter.
        response (HTTPResponse): Sanic response parameter.
    """
    response.headers["x-xss-protection"] = "1; mode=block"


def https_redirect_middleware(request: Request):
    """
    Redirects all http requests to https.

    Args:
        request (Request): Sanic request parameter.
    """
    if request.url.startswith("http://"):
        return redirect(request.url.replace("http://", "https://", 1))


def hash_password(password: str):
    """
    Securely hashes passed password to be stored.

    Args:
        password (str): Password to be hashed.

    Returns:
        hashed_password
    """
    return hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        config["SECURITY"]["SECRET"].encode("utf-8"),
        100000,
    )


def get_ip(request: Request):
    """
    Retrieves ip address from request.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        ip
    """
    return request.remote_addr if request.remote_addr else request.ip


def dir_exists(path: str):
    """
    Checks if path exists and isn't empty. Creates new path if neither of these conditions are met.

    Args:
         path (str): Path being checked.

    Returns:
        exists
    """
    try:
        os.makedirs(path)
        exists = False
    except FileExistsError:
        exists = os.listdir(path)
    return exists


def json(message: str, data, status_code: int = 200):
    """
    A preformatted Sanic json response.

    Args:
        message (int): Message describing data or relaying human readable information.
        data (Any): Raw information to be used by client.
        status_code (int): HTTP response code.
    """
    return sanic_json(
        {"message": message, "code": status_code, "data": data}, status=status_code
    )
