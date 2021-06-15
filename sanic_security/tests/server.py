from sanic import Sanic

from sanic_security.core.authentication import requires_authentication
from sanic_security.core.blueprints import security
from sanic_security.core.initializer import initialize_security
from sanic_security.core.models import Role, json, Permission
from sanic_security.core.utils import xss_prevention_middleware

app = Sanic("Sanic Security Test Server")


@app.middleware("response")
async def xxs_middleware(request, response):
    """
    Response middleware test.
    """
    xss_prevention_middleware(request, response)


@app.post("api/auth/perms")
@requires_authentication()
async def on_create_admin_perms(request, authentication_session):
    """
    Creates 'admin:update' and 'admin:add' permissions to be used for testing wildcard based authorization.
    """
    client = authentication_session.account
    await Permission().create(account=client, wildcard="admin:update", decription="")
    await Permission().create(account=client, wildcard="admin:add")
    return json("Permissions added to your account!", client.json())


@app.post("api/auth/roles")
@requires_authentication()
async def on_create_admin_roles(request, authentication_session):
    """
    Creates 'Admin' and 'Mod' roles to be used for testing role based authorization.
    """
    client = authentication_session.account
    await Role().create(account=client, name="Admin")
    await Role().create(account=client, name="Mod")
    return json("Roles added to your account!", client.json())


initialize_security(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
