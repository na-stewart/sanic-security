from sanic import Sanic

from sanic_security.core.exceptions import SecurityError
from sanic_security.core.utils import xss_prevention_middleware, https_redirect_middleware
from sanic_security.lib.tortoise import initialize_security_orm
from sanic_security.tests.blueprints import security

app = Sanic("Sanic Security Test Server")


@app.middleware("response")
async def xxs_middleware(request, response):
    """
    Xxs prevention middleware.
    """
    xss_prevention_middleware(request, response)


@app.middleware("request")
async def https_middleware(request):
    """
    Http to https redirection middleware.
    """
    # return https_redirect_middleware(request)
    pass


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
