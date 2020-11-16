import aiohttp

from amyrose.core.config import config_parser


async def send_sms(to, msg):
    account_sid = config_parser['TWILIO']['sid']
    auth_token = config_parser['TWILIO']['token']
    from_num = config_parser['TWILIO']['from']
    if account_sid and auth_token and from_num:
        auth = aiohttp.BasicAuth(login=account_sid, password=auth_token)
        async with aiohttp.ClientSession(auth=auth) as session:
            await session.post(f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json',
                               data={'From': from_num, 'To': '+' + to, 'Body': msg})
    else:
        raise RuntimeWarning('Twilio credentials not found.')
