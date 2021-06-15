from sanic import Sanic

from sanic_security.core.initializer import initialize_security
from sanic_security.core.utils import xss_prevention_middleware
from sanic_security.tests.blueprints import security

app = Sanic("Sanic Security Test Server")


@app.middleware("response")
async def xxs_middleware(request, response):
    """
    Response middleware test.
    """
    xss_prevention_middleware(request, response)


initialize_security(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
