import aiofiles
import aiohttp

from asyncauth.core.config import config
from asyncauth.core.models import AuthError


class IP2ProxyError(AuthError):
    def __init__(self, message, code):
        super().__init__(message, code)


async def retrieve_ip2proxy_bin():
    key = config['AUTH']['password']
    code = config['AUTH']['endpoint']
    async with aiohttp.ClientSession() as session:
        url = "https://www.ip2location.com/download/?token={0}&file={1}".format(key, code)
        async with session.get(url) as resp:
            if resp.status == 200:
                return await resp.read()
            else:
                raise IP2ProxyError("An error has occurred when attempting to download IP2Proxy bin.\n" +
                                    str(await resp.read()), 500)


