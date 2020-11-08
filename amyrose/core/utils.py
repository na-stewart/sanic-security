import datetime

from amyrose.lib.twilio import send_sms


def best_by(days=1):
    return datetime.datetime.utcnow() + datetime.timedelta(days=days)


def is_expired(date):
    return date < datetime.datetime.utcnow() and date


async def send_verification_code(account, verification_session):
    sms_str = 'Your verification code is: ' + str(verification_session.code)
    await send_sms(account.phone, sms_str)
