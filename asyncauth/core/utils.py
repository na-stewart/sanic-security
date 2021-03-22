import datetime
import random
import string

import bcrypt
from sanic.request import Request
from sanic_ipware import get_client_ip

from asyncauth.lib.smtp import send_email
from asyncauth.lib.twilio import send_sms


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


async def text_verification_code(account_phone: str, verification_code: str):
    """
    Sends account verification code via text.

    :param account_phone: Phone number to send code too.
    :param verification_code: Code sent to account for them to verify themselves.
    """
    sms_str = 'Your verification code is: ' + verification_code
    await send_sms(account_phone, sms_str)


async def email_verification_code(account_email: str, verification_code: str):
    """
    Sends account verification code via text.

    :param account_email: Email number to send code too.
    :param verification_code: Code sent to account for them to verify themselves.
    """
    email_str = 'Your verification code is:\n\n ' + verification_code
    await send_email(account_email, 'Account Verification', email_str)


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


def hash_password(password):
    """
    Turns passed text into hashed password
    :param password: Password to be hashed.
    :return: hashed
    """
    return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())


def str_to_list(string):
    """
    Turns passed string into an array
    :param string: string to be turned into an array
    :return: array
    """
    return string.replace(']', '').replace('[', '').replace(' ', '') \
        .replace('\'', '').replace('\"', '').split(',')
