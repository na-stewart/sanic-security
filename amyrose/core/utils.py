import datetime
import random
import string

from amyrose.lib.twilio import send_sms


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


def random_string(length=7):
    """
    Generates a random string of letters and numbers of specific length.

    :param length: The size of the random string.

    :return: random_str
    """
    return ''.join(random.choices(string.ascii_letters.lower() + string.digits, k=length))




