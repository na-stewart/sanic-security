import asyncio
import functools
import shutil

import aioIP2Proxy
import aiofiles
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from sanic_security.core.config import config
from sanic_security.core.models import SecurityError
from sanic_security.core.utils import path_exists, get_ip

ip2proxy_database = aioIP2Proxy.IP2Proxy()


class IP2ProxyError(SecurityError):
    pass


class ProxyDetectedError(IP2ProxyError):
    def __init__(self):
        super(ProxyDetectedError, self).__init__('An attempt was made to access a resource utilizing a forbidden '
                                                 'proxy.', 403)


async def cache_ip2proxy_database():
    """
    Caches a new IP2Proxy database.
    """
    code = config['IP2PROXY']['code']
    key = config['IP2PROXY']['key']
    loop = asyncio.get_running_loop()
    async with aiohttp.ClientSession() as session:
        url = "https://www.ip2location.com/download/?token={0}&file={1}".format(key, code)
        async with session.get(url) as resp:
            zip_path = './resources/security-cache/ip2proxy/ip2proxy.zip'
            async with aiofiles.open(zip_path, mode="wb") as f:
                try:
                    await f.write(await resp.read())
                    await loop.run_in_executor(None, shutil.unpack_archive, zip_path,
                                               './resources/security-cache/ip2proxy')
                except shutil.ReadError:
                    raise IP2ProxyError('Unzipping has failed due to the download rate limit or incorrect credentials.')


def initialize_ip2proxy(app):
    """
    Initializes a async cron job that runs every 00:15 GMT to refresh the IP2Proxy database.
    """
    scheduler = AsyncIOScheduler()

    @app.listener("before_server_start")
    async def init_ip2proxy_cron(app, loop):
        if not path_exists('./resources/security-cache/ip2proxy'):
            await cache_ip2proxy_database()
        scheduler.add_job(cache_ip2proxy_database, 'cron', minute='15', hour='0', month='*', week='*', day='*')
        scheduler.start()

    @app.listener("after_server_stop")
    async def shutdown_ip2proxy_cron(app, loop):
        scheduler.shutdown()


async def proxy_detection(ip: str):
    """
    Reads local database file and crosschecks passed ip address to determine if it is a known proxy.

    :param ip: Ip address being crosschecked.

    """
    await ip2proxy_database.open('./resources/security-cache/ip2proxy/' + config['IP2PROXY']['bin'])
    if await ip2proxy_database.is_proxy(ip) > 0:
        raise ProxyDetectedError()
    await ip2proxy_database.close()


def detect_proxy():
    """
    Reads local database file and crosschecks passed ip address to determine if it is a known proxy.

    :raises AccountError:

    :raises SessionError:

    :return: func(request, authentication_session, *args, **kwargs)
    """

    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(request, *args, **kwargs):
            await proxy_detection(get_ip(request))
            return await func(request, *args, **kwargs)

        return wrapped

    return wrapper


