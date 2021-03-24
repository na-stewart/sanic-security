from tortoise import Tortoise

from asyncauth.core.config import config
from asyncauth.core.utils import str_to_list


async def tortoise_init():
    """
    Initializes the tortoise-orm.
    """
    username = config['TORTOISE']['username']
    password = config['TORTOISE']['password']
    endpoint = config['TORTOISE']['endpoint']
    schema = config['TORTOISE']['schema']
    models = str_to_list(config['TORTOISE']['models'])
    await Tortoise.init(db_url='mysql://{0}:{1}@{2}/{3}'.format(username, password, endpoint, schema),
                        modules={"models": models})
    if config['TORTOISE']['generate'] == 'true':
        await Tortoise.generate_schemas()
