from asyncauth.lib.tortoise import tortoise_init

def initialize_auth(app):
    app.add_task(tortoise_init())


