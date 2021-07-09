from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from aiosmtplib import send

from sanic_security.utils import config


async def send_email(to, subj, msg, text_type="plain"):
    """
    Sends an email using SMTP.

    Args:
        to (str): Email being sent too address.
        subj (str): Email subject.
        msg (str): Email body.
        text_type (str): Can be html or plain.
    """
    message = MIMEMultipart("alternative")
    message["From"] = config["SMTP"]["from"]
    message["To"] = to
    message["Subject"] = subj
    mime_text = MIMEText(msg, text_type, "utf-8")
    message.attach(mime_text)
    await send(
        message,
        hostname=config["SMTP"]["host"],
        port=int(config["SMTP"]["port"]),
        username=config["SMTP"]["username"],
        password=config["SMTP"]["password"],
        use_tls=config["SMTP"]["tls"] == "true",
        start_tls=config["SMTP"]["start_tls"] == "true",
    )
