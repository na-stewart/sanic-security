import httpx

from sanic_security.core.utils import config


async def send_sms(to, msg):
    """
    Sends a text directly to a phone number using Twilio.

    Args:
        to (str): Phone number receiving a text, for example: 12092819472
        msg (str): Message being sent in a text.
    """
    account_sid = config["TWILIO"]["sid"]
    auth_token = config["TWILIO"]["token"]
    from_num = "+" + config["TWILIO"]["from"]
    if account_sid and auth_token and from_num:
        auth = httpx.BasicAuth(username=account_sid, password=auth_token)
        async with httpx.AsyncClient(auth=auth) as session:
            await session.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                data={"From": from_num, "To": "+" + to, "Body": msg},
            )
    else:
        raise RuntimeWarning("Twilio credentials not found.")
