import datetime
import os
import random
import string

from sanic.request import Request
from sanic_ipware import get_client_ip


def best_by(days: int = 1):
    """
    Creates an expiration date. Adds days to current datetime.

    :param days: days to be added to current time.

    :return: expiration_date
    """
    return datetime.datetime.utcnow() + datetime.timedelta(days=days)


def is_expired(date_time: datetime.datetime):
    """
    Checks if current time is beyond expiration date passed.

    :param date_time: Date to check.
    :return: expiration_date
    """
    return date_time < datetime.datetime.now(datetime.timezone.utc) and date_time


def random_str(length: int = 7):
    """
    Generates a random string of letters and numbers of specific length.

    :param length: The size of the random string.

    :return: random_str
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def request_ip(request: Request):
    """
    Retrieves the ip address of the request.

    :param request: Sanic request.
    """
    ip, routable = get_client_ip(request)
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


