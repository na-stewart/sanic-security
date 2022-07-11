from sanic import Sanic
from sanic.exceptions import SanicException
from sanic.log import logger
from sanic_ext.extensions.base import Extension
from sanic_ext import Extend

from sanic_security.configuration import Config as sanic_security_config


class ORMNotProvided():
    def __init__(self, *args, **kwargs):
        pass

    def __new__(self, *args, **kwargs):
        raise SanicException('Necessary Model not Provided')
    

class SanicSecurityExtension(Extension):
    """
    Class for the overall Security provider.

    This is mostly convienience, and wont really do anything until
     sanic-ext is updated and stabalized. At that time, the intention
     is to load this extention as a native Sanic Extension in the namespace.

    Args:
        app (Sanic): The Sanic app instance. If no provided at setup, `init_app(app)` can later be called.
        orm (str): ORM to use ['tortoise', 'umongo', 'custom'] [default: tortoise]
        account (object): Account model, properly configured for the DB used.
        session (object): Session model, properly configured for the DB used.
        role (object):  Role model, properly configured for the DB used.
        verification (object): Verification model, properly configured for the DB used.
        twostep (object): Twostep Verification model, properly configured for the DB used.
        captcha (object): Captcha Verification model, properly configured for the DB used.
        authentication (object): Authentication Verification model, properly configured for the DB used.
    
    Returns:
        Sanic-Security object, available at `current_app().ctx.extensions['security']`
    
    Raises:
        ImportError (Exception): Invalid `ORM` specified
        Exception (Exception): Missing required models for `custom` provider
    """
    logger.info("Setting up SanicSecurityExtension")
    name: str = "security"
    extension_name = app_attribute = 'security'
    app: Sanic = None

    account: object = None
    session: object = None
    role: object = None
    verification_session: object = None
    twostep_session: object = None
    captcha_session: object = None
    authentication_session: object = None
    orm = None
    _started = False

    def __init__(self, app: Sanic = None, orm = None, account: object = None, session: object = None,
                 role: object = None, verification: object = None,
                 twostep: object = None, captcha: object = None,
                 authentication: object = None):

        logger.info(f"provided app: {app}")
        logger.info(f"provided orm: {orm}")

        if app is not None:
            self.init_app(app, orm, account, session, role, verification, twostep, captcha, authentication)

    def init_app(self, app: Sanic, orm = None, account: object = None, session: object = None,
                 role: object = None, verification: object = None,
                 twostep: object = None, captcha: object = None,
                 authentication: object = None):
        """
        init_app factory

        See main object for Args
        """
        logger.info("[Sanic-Security] init_app")

        if app is None or not isinstance(app, Sanic):
            raise Exception(f"Sanic instance must be provided")

        self.app = app
        self.app.config.update(sanic_security_config())

        self.account = account if account else self.app.config.get('SANIC_SECURITY_ACCOUNT_MODEL', None)
        self.session = session if session else self.app.config.get('SANIC_SECURITY_SESSION_MODEL', None)
        self.role = role if role else self.app.config.get('SANIC_SECURITY_ROLE_MODEL', None)
        self.verification_session = verification if verification else self.app.config.get('SANIC_SECURITY_VERIFICATION_MODEL', None)
        self.twostep_session = twostep if twostep else self.app.config.get('SANIC_SECURITY_TWOSTEP_MODEL', None)
        self.captcha_session = captcha if captcha else self.app.config.get('SANIC_SECURITY_CAPTCHA_MODEL', None)
        self.authentication_session = authentication if authentication else self.app.config.get('SANIC_SECURITY_AUTHENTICATION_MODEL', None)
        self.orm = orm if orm else self.app.config.get('SANIC_SECURITY_ORM', 'tortoise')
        try:
            # TODO: this is ugly as hell, but works for now
            logger.info(f"attmpeting to import sanic_security.ORM.{self.orm}")
            if self.orm == 'custom':
                if not self.role:
                    raise Exception('Custom ORM specified, but required model Role was not provided!')
                if not self.account:
                    raise Exception('Custom ORM specified, but required model Account was not provided!')
                if not self.verification_session:
                    self.verification_session = ORMNotProvided()
                if not self.twostep_session:
                    self.twostep_session = ORMNotProvided()
                if not self.captcha_session:
                    self.captcha_session = ORMNotProvided()
                if not self.authentication_session:
                    self.authentication_session = ORMNotProvided()
            else:
                if self.orm == 'tortoise':
                    from .orm.tortoise import Role, Account, VerificationSession, TwoStepSession, CaptchaSession, AuthenticationSession
                elif self.orm == 'umongo':
                    from .orm.umongo import Role, Account, VerificationSession, TwoStepSession, CaptchaSession, AuthenticationSession
                else:
                    raise ImportError("Invalid ORM specified")
    
                self.role = Role()
                self.account = Account()
                self.verification_session = VerificationSession()
                self.twostep_session = TwoStepSession()
                self.captcha_session = CaptchaSession()
                self.authentication_session = AuthenticationSession()

        except ImportError as e:
            logger.critical(f"No such ORM provider: {orm}")
            raise e
        except Exception as e:
            logger.critical(f"Sanic-Security ORM Setup Failure: {e}")
            raise e
        
        self._register_extension(self.app)

    def label(self):
        return "Sanic-Security"

    def _register_extension(self, app):
        logger.info("Trying to register Security Extension")
        if not hasattr(app.ctx, 'extensions'):
            setattr(app.ctx, 'extensions', {})
        app.ctx.extensions[self.extension_name] = self

    def startup(self, bootstrap: Extend) -> None:
        """
        Used by sanic-ext to start up an extension
        NOT YET WORKING -- SANIC-EXT issue, not mine
        """
        logger.debug(f"Bootstrap: {dir(bootstrap)}")
