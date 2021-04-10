from sanic import Sanic

from sanicsecurity.core.config import config
from sanicsecurity.core.models import Session
from sanicsecurity.lib.ip2proxy import initialize_ip2proxy
from sanicsecurity.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security.

    :param app: Sanic object used to add tasks too.
    """
    if config.has_section('IP2PROXY'):
        app.add_task(initialize_ip2proxy())
    initialize_tortoise(app)
    Session.initialize_cache(app)
