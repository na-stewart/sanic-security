import hashlib
import os
from configparser import ConfigParser

from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse

config = ConfigParser()
config.read("./security.ini")


def hash_password(password: str) -> bytes:
    """
    Securely hashes password to be stored.

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


def get_ip(request: Request) -> str:
    """
    Retrieves ip address from client request.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        ip
    """
    return request.remote_addr if request.remote_addr else request.ip


def dir_exists(path: str) -> bool:
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


def json(message: str, data, status_code: int = 200) -> HTTPResponse:
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
