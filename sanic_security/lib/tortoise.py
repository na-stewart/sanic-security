from sanic import Sanic
from tortoise import Tortoise

from sanic_security.core.utils import config


def initialize_tortoise(app: Sanic):
    """
    Initializes tortoise-orm.

    Args:
        app (Sanic): Sanic Framework app.
    """

    @app.listener("before_server_start")
    async def init_orm(app, loop):
        username = config["TORTOISE"]["username"]
        password = config["TORTOISE"]["password"]
        endpoint = config["TORTOISE"]["endpoint"]
        schema = config["TORTOISE"]["schema"]
        engine = config["TORTOISE"]["engine"]
        models = config["TORTOISE"]["models"].replace(" ", "").split(",")
        url = engine + "://{0}:{1}@{2}/{3}".format(username, password, endpoint, schema)
        await Tortoise.init(db_url=url, modules={"models": models})
        if config["TORTOISE"]["generate"] == "true":
            await Tortoise.generate_schemas()

    @app.listener("after_server_stop")
    async def close_orm(app, loop):
        await Tortoise.close_connections()
