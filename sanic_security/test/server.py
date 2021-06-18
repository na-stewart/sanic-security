from sanic import Sanic

from sanic_security.blueprints import security
from sanic_security.exceptions import SecurityError
from sanic_security.lib.tortoise import initialize_security_orm

app = Sanic("test")


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
