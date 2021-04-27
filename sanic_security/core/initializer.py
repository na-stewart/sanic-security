from sanic import Sanic

from sanic_security.core.config import config
from sanic_security.core.models import Session
from sanic_security.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security.

    :param app: Sanic object used to add tasks too.
    """
    initialize_tortoise(app)
    Session.initialize_cache(app)

