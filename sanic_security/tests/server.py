from sanic import Sanic, text

from sanic_security.exceptions import SecurityError
from sanic_security.lib.smtp import send_email
from sanic_security.lib.twilio import send_sms
from sanic_security.utils import xss_prevention_middleware
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


@app.post("api/test/text")
async def on_text(request):
    """
    Sends test message text to phone number.
    """
    await send_sms(request.form.get('to'), 'Test message')
    return text("Text message sent.")


@app.post("api/test/email")
async def on_email(request):
    """
    Sends test message to email address.
    """
    await send_email(request.form.get('to'), 'test', 'Test message')
    return text("Email sent.")


@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response


initialize_security_orm(app)
app.blueprint(security)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, workers=4)
