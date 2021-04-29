from sanic import Sanic

from sanic_security.core.models import CaptchaSession, TwoStepSession
from sanic_security.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security and related processes.

    :param app: Sanic object used to add tasks too.
    """
    initialize_tortoise(app)
    TwoStepSession.initialize_cache(app)
    CaptchaSession.initialize_cache(app)

