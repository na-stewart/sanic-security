from tortoise import Tortoise

from amyrose.core.cache import config_parser, read_config


async def tortoise_init():
    username = config_parser['TORTOISE']['username']
    password = config_parser['TORTOISE']['password']
    endpoint = config_parser['TORTOISE']['endpoint']
    schema = config_parser['TORTOISE']['schema']
    await Tortoise.init(db_url='mysql://{0}:{1}@{2}/{3}'.format(username, password, endpoint, schema),
                        modules={"models": ['amyrose.core.models']})
    if config_parser['TORTOISE']['generate'] == 'true':
        await Tortoise.generate_schemas()
