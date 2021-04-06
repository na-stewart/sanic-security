import asyncio
import string
from random import random

import aiofiles
from captcha.image import ImageCaptcha

from asyncauth.core.config import config
from asyncauth.core.utils import path_exists
from asyncauth.lib.ip2proxy import retrieve_ip2proxy_bin

auth_cache_path = './resources/auth-cache/'


async def initialize_ip2proxy_cache():
    """
    Caches a new IP2Proxy database every 00:15 GMT.
    """
    ip2proxy_cache_path = auth_cache_path + 'ip2proxy/'
    while True:
        if path_exists(ip2proxy_cache_path):
            ip2proxy_bin = await retrieve_ip2proxy_bin()
            async with aiofiles.open(ip2proxy_cache_path + 'IP2PROXY.BIN', mode="w") as f:
                await f.write(ip2proxy_bin)
        else:
            continue
        await asyncio.sleep(4500)


async def initialize_session_cache():
    """
    Caches up to 100 code and image variations.
    """
    loop = asyncio.get_running_loop()
    session_cache_path = auth_cache_path + 'session/'
    image = ImageCaptcha(190, 90, fonts=[config['AUTH']['captcha_font']])
    if not path_exists(session_cache_path):
        async with aiofiles.open(session_cache_path + 'codes.txt', mode="w") as f:
            for i in range(100):
                code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                await f.write(code + ' ')
                await loop.run_in_executor(None, image.write, code[:6], session_cache_path + code[:6] + '.png')


async def get_cached_session_code():
    """
    Retrieves a random cached code from a codes.txt file

    :return: code
    """
    async with aiofiles.open(auth_cache_path + 'session/codes.txt', mode='r') as f:
        codes = await f.read()
        return random.choice(codes.split())
