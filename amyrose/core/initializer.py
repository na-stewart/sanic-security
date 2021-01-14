from amyrose.core.captcha import captcha_init
from amyrose.core.verification import verification_init
from amyrose.lib.tortoise import tortoise_init


def initialize(app):
    app.add_task(tortoise_init())
    app.add_task(verification_init())
    app.add_task(captcha_init())


