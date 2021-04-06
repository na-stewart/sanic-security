import aiohttp
from IP2Proxy import IP2Proxy

from asyncauth.core.config import config
from asyncauth.core.models import ForbiddenConnectionError

ip2proxy_database = IP2Proxy()


def ip2proxy_crosscheck(ip: str, *args: str):
    ip2proxy_database.open('./resources/auth-cache/ip2proxy/IP2PROXY.bin')
    if ip2proxy_database.is_proxy(ip) != 0:
        if not args or ip2proxy_database.get_proxy_type(ip) not in args:
            raise ForbiddenConnectionError('You are attempting to access a resource from a forbidden proxy.')
    ip2proxy_database.close()


async def retrieve_ip2proxy_bin():
    key = config['IP2PROXY']['key']
    code = config['IP2PROXY']['code']
    async with aiohttp.ClientSession() as session:
        url = "https://www.ip2location.com/download/?token={0}&file={1}".format(key, code)
        async with session.get(url) as resp:
            if resp.status == 200:
                return await resp.read()
            else:
                raise Exception("Could not download IP2Proxy database.\n" + str(await resp.read()))
