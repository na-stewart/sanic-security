from sanic import Sanic

from asyncauth.core.cache import initialize_session_cache
from asyncauth.lib.tortoise import initialize_tortoise


def initialize_auth(app: Sanic):
    """
    Initializes Async Auth.
    :param app: Sanic object used to add tasks too.
    """
    app.add_task(initialize_tortoise(app))
    app.add_task(initialize_session_cache())
