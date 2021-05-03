from sanic import Sanic

from sanic_security.core.models import CaptchaSession, TwoStepSession
from sanic_security.lib.tortoise import initialize_tortoise


def initialize_security(app: Sanic):
    """
    Starts all initial Sanic Security processes such as initializing tortoise and caches.

    Args:
        app (Sanic): Sanic Framework app.
    """
    initialize_tortoise(app)
    TwoStepSession.initialize_cache(app)
    CaptchaSession.initialize_cache(app)
