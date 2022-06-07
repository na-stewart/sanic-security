import importlib

from sanic import Sanic
from sanic.log import logger
from sanic_ext.extensions.base import Extension

from sanic_security.configuration import Config as sanic_security_config


class SanicSecurityExtension(Extension):
    logger.info("Setting up SanicSecurityExtension")
    name: str = "SanicSecurity"
    extension_name = app_attribute = 'SanicSecurity'
    app: Sanic = None

    account = None
    session = None
    role = None
    verification_session = None
    twostep_session = None
    captcha_session = None
    authentication_session = None

    def __init__(self, app: Sanic, orm = None, account = None, session = None,
                 role = None, verification = None,
                 twostep = None, captcha = None,
                 authentication = None):

        logger.info(f"provided app: {app}")
        logger.info(f"provided orm: {orm}")
        logger.info(f"env orm: {app.config.get('SANIC_SECURITY_ORM', None)}")
        app.config.update(sanic_security_config())
        logger.info(app.config)
        self.app = app
        self.account = account if account else app.config.get('SANIC_SECURITY_ACCOUNT_MODEL', None)
        self.session = session if session else app.config.get('SANIC_SECURITY_SESSION_MODEL', None)
        self.role = role if role else app.config.get('SANIC_SECURITY_ROLE_MODEL', None)
        self.verification_session = verification if verification else app.config.get('SANIC_SECURITY_VERIFICATION_MODEL', None)
        self.twostep_session = twostep if twostep else app.config.get('SANIC_SECURITY_TWOSTEP_MODEL', None)
        self.captcha_session = captcha if captcha else app.config.get('SANIC_SECURITY_CAPTCHA_MODEL', None)
        self.authentication_session = authentication if authentication else app.config.get('SANIC_SECURITY_AUTHENTICATION_MODEL', None)
        self.orm = orm if orm else app.config.get('SANIC_SECURITY_ORM', 'tortoise')
        try:
            self.orm = importlib.import_module(f'sanic_security.orm.{self.orm}') 
        except ImportError as e:
            logger.error(f"No such ORM provider: {orm}")
            raise e
        self.startup()

    def label(self):
        return "Sanic-Security"

    def startup(self):
        """
        Used by sanic-ext to start up an extension
        """
        logger.info("[Sanic-Security] init_app")

        @self.app.listener('before_server_start')
        async def security_configure(app_inner, loop):
            pass