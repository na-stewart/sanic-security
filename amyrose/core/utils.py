import datetime
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

    :param date_time:
    :return:
    """
    return date_time < datetime.datetime.now(datetime.timezone.utc) and date_time


async def text_verification_code(account_phone: str, verification_code: str):
    """
    Sends account verification code via text.

    :param account: Phone number to send code too.
    :param verification_code: Code sent to account for them to verify themselves.
    """
    sms_str = 'Your verification code is: ' + verification_code
    await send_sms(account_phone, sms_str)


