import aioIP2Proxy
import aiofiles
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from asyncauth.core.config import config
from asyncauth.core.models import AuthError
from asyncauth.core.utils import path_exists, get_ip

ip2proxy_database = aioIP2Proxy.IP2Proxy()


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
            response = await resp.read()
            if response == b'NO PERMISSION':
                raise IP2ProxyError('Could not download IP2Proxy database due to incorrect credentials.', 500)
            else:
                async with aiofiles.open('./resources/auth-cache/ip2proxy/IP2PROXY.bin', mode="wb") as f:
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


async def ip2proxy_middleware(request):
    await ip2proxy_database.open('./resources/auth-cache/ip2proxy/IP2PROXY.bin')
    rec = await ip2proxy_database.is_proxy("1.0.0.8")
    print(ip2proxy_database.get_database_version())
    print(await ip2proxy_database.is_proxy("1.0.0.8"))
    if await ip2proxy_database.is_proxy(get_ip(request)) > 0:
        raise IP2ProxyError('You are attempting to access a resource from a forbidden proxy.', 403)
    await ip2proxy_database.close()
