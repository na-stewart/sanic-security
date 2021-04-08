from sanic import Sanic
from asyncauth.core.config import config
from asyncauth.core.models import Session
from asyncauth.lib.ip2proxy import initialize_ip2proxy_cache
from asyncauth.lib.tortoise import initialize_tortoise


def initialize_auth(app: Sanic):
    """
    Initializes Async Auth.
    :param app: Sanic object used to add tasks too.
    """

    app.add_task(initialize_tortoise(app))
    app.add_task(Session.initialize_cache())
    if config.has_section('IP2PROXY'):
        app.add_task(initialize_ip2proxy_cache())

