import json

import httpx

from sanic_security.utils import config


class TwillioError(Exception):
    pass


async def send_sms(to, msg):
    """
    Sends a text directly to a phone number using Twilio.

    Args:
        to (str): Phone number receiving a text, for example: 12092819472
        msg (str): Message being sent in a text.
    """
    account_sid = config["TWILIO"]["sid"]
    auth_token = config["TWILIO"]["token"]
    from_num = f"+{config['TWILIO']['from']}"
    if account_sid and auth_token and from_num:
        auth = httpx.BasicAuth(username=account_sid, password=auth_token)
        async with httpx.AsyncClient(auth=auth) as session:
            post = await session.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                data={"From": from_num, "To": f"+{to}", "Body": msg},
            )
            if post.status_code != 201:
                raise TwillioError(json.loads(post.content)["message"])
    else:
        raise RuntimeWarning("Twilio credentials not found.")
