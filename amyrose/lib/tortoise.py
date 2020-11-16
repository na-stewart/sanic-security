from tortoise import Tortoise

from amyrose.core.config import config_parser


async def tortoise_init():
    username = config_parser['TORTOISE']['username']
    password = config_parser['TORTOISE']['password']
    endpoint = config_parser['TORTOISE']['endpoint']
    schema = config_parser['TORTOISE']['schema']
    models_str = config_parser['TORTOISE']['models'].replace(']', '').replace('[', '').replace(' ', '')\
        .replace('\'', '').replace('\"', '')
    await Tortoise.init(db_url='mysql://{0}:{1}@{2}/{3}'.format(username, password, endpoint, schema),
                        modules={"models": models_str.split(",")})
    if config_parser['TORTOISE']['generate'] == 'true':
        await Tortoise.generate_schemas()
