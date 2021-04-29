import asyncio
import os
import random

import aiofiles
from captcha.image import ImageCaptcha
from sanic import Sanic

from sanic_security.core.config import config
from sanic_security.core.models import VerificationSession




def initialize_session_cache(app: Sanic):
    """
    Caches up to 100 code and image variations.
    """

    @app.listener("before_server_start")
    async def generate_codes(app, loop):
        loop = asyncio.get_running_loop()
        image = ImageCaptcha(190, 90, fonts=[config['AUTH']['captcha_font']])

        if not os.path.exists(cache_path):
            os.makedirs(cache_path)
            async with aiofiles.open(cache_path + 'codes.txt', mode="w") as f:
                for i in range(100):
                    code = ''.join(random.choices('123456789qQeErRtTyYuUiIpPaAdDfFgGhHkKlLbBnN', k=8))
                    await f.write(code + ' ')
                    await loop.run_in_executor(None, image.write, code[:6], cache_path + code[:6] + '.png')


async def get_session_cache_code():
    """
    Retrieves a random cached code from a codes.txt file

    :return: code
    """
    async with aiofiles.open(VerificationSession.cache_path + 'codes.txt', mode='r') as f:
        codes = await f.read()
        return random.choice(codes.split())
