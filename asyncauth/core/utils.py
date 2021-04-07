import os

from sanic.request import Request
from sanic_ipware import get_client_ip

from asyncauth.core.config import config




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
