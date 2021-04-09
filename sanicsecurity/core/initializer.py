from sanic import Sanic

from sanicsecurity.core.models import Session
from sanicsecurity.lib.ip2proxy import initialize_ip2proxy_cache
from sanicsecurity.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security.
    :param app: Sanic object used to add tasks too.
    """

    initialize_tortoise(app)
    Session.initialize_cache(app)
    app.add_task(initialize_ip2proxy_cache())

