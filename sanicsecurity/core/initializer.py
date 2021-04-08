from sanic import Sanic

from sanicsecurity.core.models import Session
from sanicsecurity.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security.
    :param app: Sanic object used to add tasks too.
    """

    app.add_task(initialize_tortoise(app))
    app.add_task(Session.initialize_cache())

