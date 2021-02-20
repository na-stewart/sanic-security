from tortoise import Tortoise

from amyrose.core.config import config_parser
from amyrose.core.utils import str_to_list


async def tortoise_init():
    username = config_parser['TORTOISE']['username']
    password = config_parser['TORTOISE']['password']
    endpoint = config_parser['TORTOISE']['endpoint']
    schema = config_parser['TORTOISE']['schema']
    models = str_to_list(config_parser['TORTOISE']['models'])
    await Tortoise.init(db_url='mysql://{0}:{1}@{2}/{3}'.format(username, password, endpoint, schema),
                        modules={"models": models})
    if config_parser['TORTOISE']['generate'] == 'true':
        await Tortoise.generate_schemas()
