import aiohttp

from sanic_security.core.config import config


async def send_sms(to, msg):
    """
    Sends a text directly to a phone number using Twilio.

    :param to: The phone number receiving a text, for example: +12092819472.
    :param msg: The message to be sent as a text.
    """
    account_sid = config['TWILIO']['sid']
    auth_token = config['TWILIO']['token']
    from_num = '+' + config['TWILIO']['from']
    if account_sid and auth_token and from_num:
        auth = aiohttp.BasicAuth(login=account_sid, password=auth_token)
        async with aiohttp.ClientSession(auth=auth) as session:
            await session.post(f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json',
                               data={'From': from_num, 'To': '+' + to, 'Body': msg})
    else:
        raise RuntimeWarning('Twilio credentials not found.')
