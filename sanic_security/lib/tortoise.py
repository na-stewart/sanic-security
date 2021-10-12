from sanic import Sanic
from sanic.log import logger
from tortoise import Tortoise

from sanic_security.utils import config

"""
Copyright (C) 2021 Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""


def initialize_security_orm(app: Sanic):
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
        url = f"{engine}://{username}:{password}@{endpoint}/{schema}"
        await Tortoise.init(db_url=url, modules={"models": models})
        if config["TORTOISE"].getboolean("generate"):
            await Tortoise.generate_schemas()
        logger.info("Sanic Security ORM initialised")

    @app.listener("after_server_stop")
    async def close_orm(app, loop):
        await Tortoise.close_connections()
