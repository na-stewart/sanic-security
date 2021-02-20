import functools
import os
import random

import aiofiles
from captcha.image import ImageCaptcha
from sanic.request import Request

from amyrose.core.config import config_parser
from amyrose.core.dto import CaptchaSessionDTO
from amyrose.core.models import CaptchaSession
from amyrose.core.utils import random_str, request_ip, str_to_list

captcha_session_dto = CaptchaSessionDTO()
captcha_cache_path = './resources/captcha/'



async def captcha_init():
    """
    Generates up to 100 captcha variations as string and image within their respective folders if empty.
    """
    fonts = str_to_list(config_parser['ROSE']['fonts']) if config_parser['ROSE']['fonts'] else None
    image = ImageCaptcha(fonts=fonts)
    if not os.path.exists(captcha_cache_path):
        os.makedirs(captcha_cache_path + '/img')
        async with aiofiles.open(captcha_cache_path + 'captcha.txt', mode="w") as f:
            for i in range(100):
                random_string = random_str(5)
                await f.write(random_string + '\n' if i < 99 else random_string)
                image.write(random_string, captcha_cache_path + 'img/' + random_string + '.png')


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    :param request: Sanic request parameter.

    :return: account, captcha_session
    """
    random_captcha = await random_cached_captcha()
    captcha_session = await captcha_session_dto.create(ip=request_ip(request), captcha=random_captcha)
    return captcha_session


def requires_captcha():
    """
    Has the same function as the authenticate method, but is in the form of a decorator and authenticates client.

    :raises AccountError:

    :raises SessionError:
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await captcha(request)
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


async def captcha(request: Request):
    """
    Validated captcha challenge attempt. Captcha is unusable after 5 attempts.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following arguments:
    captcha.

    :return: account, captcha_session
    """
    params = request.form
    captcha_session = await CaptchaSession().decode(request)
    CaptchaSession.ErrorFactory().raise_error(captcha_session)
    if captcha_session.captcha != params.get('captcha'):
        await _on_failed_captcha_attempt(captcha_session)
    else:
        captcha_session = await captcha_session_dto.update(captcha_session.uid, valid=False)
        return captcha_session


async def _on_failed_captcha_attempt(captcha_session):
    attempts = captcha_session.attempts + 1
    print(attempts)
    if attempts > 5:
        raise CaptchaSession.MaximumAttemptsError()
    else:
        await captcha_session_dto.update(captcha_session.uid, attempts=attempts)
    raise CaptchaSession.IncorrectCaptchaError()


async def random_cached_captcha():
    """
    Retrieves a random captcha from the generated captcha list,

    :return: captcha_str
    """
    async with aiofiles.open(captcha_cache_path + 'captcha.txt', mode="r") as f:
        return random.choice([line.strip() async for line in f])


def get_captcha_image(captcha):
    """
    Retrieves image path of captcha.
    """
    return captcha_cache_path + 'img/' + captcha.captcha + '.png'
