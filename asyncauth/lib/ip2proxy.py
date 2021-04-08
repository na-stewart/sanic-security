import aiofiles
import aiohttp
from IP2Proxy import IP2Proxy
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from asyncauth.core.config import config
from asyncauth.core.models import AuthError
from asyncauth.core.utils import path_exists

ip2proxy_database = IP2Proxy()


class IP2ProxyError(AuthError):
    pass


async def cache_ip2proxy_database():
    """
    Caches a new IP2Proxy database.
    """
    key = config['IP2PROXY']['key']
    code = config['IP2PROXY']['code']
    async with aiohttp.ClientSession() as session:
        url = "https://www.ip2location.com/download/?token={0}&file={1}".format(key, code)
        async with session.get(url) as resp:
            async with aiofiles.open('./resources/auth-cache/ip2proxy/IP2PROXY.BIN', mode="wb") as f:
                response = await resp.read()
                if response == b'NO PERMISSION':
                    raise IP2ProxyError('Could not download IP2Proxy database due to incorrect credentials.', 500)
                else:
                    await f.write(await resp.read())


async def initialize_ip2proxy_cache():
    """
    Initializes a async cron job that runs every 00:15 GMT to refresh the IP2Proxy database.
    """
    if not path_exists('./resources/auth-cache/ip2proxy/'):
        await cache_ip2proxy_database()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(cache_ip2proxy_database, 'cron', minute='15', hour='0', month='*', week='*', day='*')
    scheduler.start()


# TODO make asynchronous
def ip2proxy_middleware(ip: str, *args: str):
    ip2proxy_database.open('./resources/auth-cache/ip2proxy/IP2PROXY.bin')
    if ip2proxy_database.is_proxy(ip) != 0:
        if not args or ip2proxy_database.get_proxy_type(ip) not in args:
            raise IP2ProxyError('You are attempting to access a resource from a forbidden proxy.', 403)
    ip2proxy_database.close()
