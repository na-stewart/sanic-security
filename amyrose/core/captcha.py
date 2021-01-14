import os
import random

import aiofiles
from captcha.image import ImageCaptcha
from sanic.request import Request

from amyrose.core.dto import CaptchaSessionDTO
from amyrose.core.models import CaptchaSession
from amyrose.core.utils import random_string

captcha_session_dto = CaptchaSessionDTO()
captcha_cache_path = '../resources/captcha/'
image = ImageCaptcha()


async def captcha_init():
    """
    Generates up to 100 captcha variations as string and image within their respective folders if empty.
    """
    if not os.path.exists(captcha_cache_path):
        os.makedirs(captcha_cache_path + '/img')
        async with aiofiles.open(captcha_cache_path + 'captcha.txt', mode="w") as f:
            for i in range(100):
                random_str = random_string(5)
                await f.write(random_str + '\n' if i < 99 else random_str)
                image.write(random_str, '../resources/captcha/' + 'img/' + random_str + '.png')


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    :param request: Sanic request parameter.

    :return: account, captcha_session
    """
    captcha_challenge = await random_captcha()
    captcha_session = await captcha_session_dto.create(ip=request.ip, challenge=captcha_challenge)
    return captcha_session


async def _complete_failed_captcha_attempt(captcha_session):
    captcha_session.attempts += 1
    if captcha_session.attempts > 5:
        raise CaptchaSession.MaximumAttemptsError()
    else:
        await captcha_session_dto.update(captcha_session, ['attempts'])
    raise CaptchaSession.ChallengeAttemptError()


async def captcha(request: Request):
    """
    Validated captcha challenge attempt. Captcha is invalid after 5 attempts.

    :param request: Sanic request parameter.

    :return: account, captcha_session
    """
    params = request.form
    captcha_session = await CaptchaSession().decode(request)
    CaptchaSession.ErrorFactory().raise_error(captcha_session)
    if captcha_session.challenge != params.get('captcha'):
        await _complete_failed_captcha_attempt(captcha_session)
    else:
        captcha_session.valid = False
        await captcha_session_dto.update(captcha_session, ['valid'])
        return captcha_session


async def random_captcha():
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
    return '../resources/captcha/img/' + captcha.challenge + '.png'
