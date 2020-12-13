import datetime

from amyrose.lib.twilio import send_sms


def url_endpoint(url):
    split_url = url.rpartition('/')
    return split_url[1] + split_url[2]


def best_by(days=1):
    return datetime.datetime.utcnow() + datetime.timedelta(days=days)


def is_expired(date_time):
    return date_time < datetime.datetime.now(datetime.timezone.utc) and date_time


async def text_verification_code(account, verification_session):
    sms_str = 'Your verification code is: ' + str(verification_session.code)
    await send_sms(account.phone, sms_str)
