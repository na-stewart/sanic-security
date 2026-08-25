import datetime
import os
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import ascii_uppercase, digits, Template

import aiosmtplib
from argon2 import PasswordHasher
from captcha.audio import AudioCaptcha
from captcha.image import ImageCaptcha
from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse
from sanic.utils import str_to_bool as sanic_str_to_bool

from sanic_security.configuration import config

"""
Copyright (c) 2020-Present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

image_generator: ImageCaptcha = ImageCaptcha(
    190, 90, fonts=config.CAPTCHA_FONT.replace(" ", "").split(",")
)
audio_generator: AudioCaptcha = AudioCaptcha(voicedir=config.CAPTCHA_VOICE)
password_hasher: PasswordHasher = PasswordHasher()


def get_ip(request: Request) -> str:
    """
    Retrieves ip address from client request.

    Args:
        request (Request): Sanic request parameter.

    Returns:
        ip
    """
    return request.remote_addr or request.ip


def get_code(digits_only: bool = False) -> str:
    """
    Generates random code to be used for verification.

    Args:
        digits_only: Determines if code should only contain digits.

    Returns:
        code
    """
    return "".join(
        secrets.choice(("" if digits_only else ascii_uppercase) + digits)
        for _ in range(6)
    )


def is_expired(date):
    """
    Checks if current date has surpassed the date passed into the function.

    Args:
        date: The date being checked for expiration.

    Returns:
        is_expired
    """
    return date and datetime.datetime.now(datetime.timezone.utc) >= date


def get_expiration_date(seconds: int) -> datetime.datetime:
    """
    Retrieves the date after which something (such as a session) is no longer valid.

    Args:
        seconds: Seconds added to current time.

    Returns:
        expiration_date
    """
    return (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=seconds)
        if seconds > 0
        else None
    )


def str_to_bool(val: str) -> bool:
    """Returns false if val is None instead of raising ValueError (Sanic's implementation)."""
    return sanic_str_to_bool(val) if val else False


def json(message: str, data, status_code: int = 200) -> HTTPResponse:
    """
    A preformatted Sanic json response.

    Args:
        message (str): Message describing data or relaying human-readable information.
        data (Any): Raw information to be used by client.
        status_code (int): HTTP response code.

    Returns:
        json
    """
    return sanic_json(
        {"message": message, "code": status_code, "data": data}, status=status_code
    )


async def send_email(to_address, subject, data):
    """
    Sends an email to a given address. Renders an HTML template from config.TEMPLATE_PATH if it exists, substituting
    values from data. Otherwise, raw text will be sent.

    Args:
        to_address (str): Recipient's email address.
        subject (str): Subject line of the email.
        data (dict | str): Substitution values for the template if one exists, otherwise the plain text body.
    """
    msg = MIMEMultipart()
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_address
    msg["Subject"] = subject
    if os.path.exists(config.TEMPLATE_PATH):
        with open(config.TEMPLATE_PATH, "r", encoding="utf-8") as f:
            html_content = Template(f.read()).safe_substitute(data)
        msg.attach(MIMEText(html_content, "html"))
    else:
        msg.attach(MIMEText(data, "plain"))
    await aiosmtplib.send(
        msg,
        hostname=config.SMTP_HOSTNAME,
        port=config.SMTP_PORT,
        start_tls=config.SMTP_START_TLS,
        username=config.SMTP_USERNAME,
        password=config.SMTP_PASSWORD,
    )
