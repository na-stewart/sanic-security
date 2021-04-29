from sanic import Sanic

from sanic_security.core.config import config
from sanic_security.core.models import Session, CaptchaSession, TwoStepSession
from sanic_security.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Initializes sanic-security.

    :param app: Sanic object used to add tasks too.
    """
    initialize_tortoise(app)
    CaptchaSession.Cache().initialize(app)
    TwoStepSession.Cache().initialize(app)

