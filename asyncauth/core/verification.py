import functools
import os
import random

import aiofiles
from captcha.image import ImageCaptcha
from sanic.request import Request

from asyncauth.core.config import config
from asyncauth.core.models import Account, VerificationSession, CaptchaSession
from asyncauth.core.utils import random_str, request_ip, str_to_list

resources_path = './resources'


async def verification_init():
    await generate_random_codes('/verification', 7)
    await generate_random_codes('/captcha', 5)
    await generate_captcha_images()


async def generate_random_codes(path: str, length: int):
    """
    Generates up to 100 verification code variations in a codes.txt file
    """
    path = resources_path + path
    if not os.path.exists(path):
        os.makedirs(path)
        async with aiofiles.open(path + '/codes.txt', mode="w") as f:
            for i in range(100):
                random_string = random_str(length)
                await f.write(random_string + '\n' if i < 99 else random_string)


async def get_random_code(path: str):
    """
    Retrieves a random verification code from a codes.txt file

    :return: verification_code_str
    """
    path = resources_path + path
    async with aiofiles.open(path + '/codes.txt', mode="r") as f:
        return random.choice([line.strip() async for line in f])


async def request_verification(request: Request, account: Account):
    """
    Creates a verification session associated with an account. Renders account unverified.

    :param request: Sanic request parameter.

    :param account: The account that requires verification. If none, will retrieve account from verification or
    authentication session.

    :return: verification_session
    """
    account.verified = False
    await account.save(update_fields=['verified'])
    verification_session = await VerificationSession.create(code=await get_random_code('/verification'),
                                                            account=account, ip=request_ip(request))
    return verification_session


async def verify_account(request: Request):
    """
    Verifies an account for use using a code sent via email or text.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :raises SessionError:

    :return: verification_session
    """

    verification_session = await VerificationSession().decode(request)
    if verification_session.code != request.form.get('code'):
        raise VerificationSession.VerificationAttemptError()
    else:
        VerificationSession.ErrorFactory(verification_session)
    verification_session.account.verified = True
    verification_session.valid = False
    await verification_session.account.save(update_fields=['verified'])
    await verification_session.save(update_fields=['valid'])
    return verification_session


def try_to_get_captcha_fonts():
    try:
        return str_to_list(config['AUTH']['captcha_fonts'])
    except KeyError:
        return None


async def generate_captcha_images():
    """
    Retrieves a random verification code from a codes.txt file

    :return: verification_code_str
    """
    image = ImageCaptcha(fonts=try_to_get_captcha_fonts())
    async with aiofiles.open(resources_path + 'captcha/codes.txt', mode="r") as f:
        async for captcha_challenge in f:
            image.write(captcha_challenge, resources_path + 'captcha/img/' + captcha_challenge + '.png')


async def request_captcha(request: Request):
    """
    Creates a captcha session associated with an account.

    :param request: Sanic request parameter.

    :return: captcha_session
    """
    random_captcha = await get_random_code('/captcha')
    captcha_session = await CaptchaSession.create(ip=request_ip(request), captcha=random_captcha)
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

    :return: captcha_session
    """
    params = request.form
    captcha_session = await CaptchaSession().decode(request)
    CaptchaSession.ErrorFactory(captcha_session)
    if captcha_session.captcha != params.get('captcha'):
        attempts = captcha_session.attempts + 1
        if attempts > 5:
            raise CaptchaSession.MaximumAttemptsError()
        else:
            captcha_session.attempts = attempts
            await captcha_session.save(update_fields=['attempts'])
            raise CaptchaSession.IncorrectCaptchaError()
    else:
        captcha_session.valid = False
        await captcha_session.save(update_fields=['valid'])
    return captcha_session
