from os import environ

from sanic.utils import str_to_bool

DEFAULT_CONFIG = {
    "SECRET": "This is a big secret. Shhhhh",
    "CACHE": "./security-cache",
    "SESSION_SAMESITE": "strict",
    "SESSION_SECURE": False,
    "SESSION_HTTPONLY": True,
    "SESSION_DOMAIN": None,
    "SESSION_EXPIRES_ON_CLIENT": False,
    "SESSION_PREFIX": "token",
    "SESSION_ENCODING_ALGORITHM": "HS256",
    "CAPTCHA_SESSION_EXPIRATION": 60,
    "CAPTCHA_FONT": "captcha.ttf",
    "TWO_STEP_SESSION_EXPIRATION": 200,
    "AUTHENTICATION_SESSION_EXPIRATION": 2592000,
    "ALLOW_LOGIN_WITH_USERNAME": False,
    "DATABASE_URL": "sqlite://:memory:",
}


class Config(dict):
    """
    Sanic Security configuration.

    Attributes:
        SECRET (str): The secret used by the hashing algorithm for generating and signing JWTs. This should be a string unique to your application. Keep it safe.
        CACHE (str): The path used for caching.
        SESSION_SAMESITE (str): The SameSite attribute of session cookies.
        SESSION_SECURE (bool): The Secure attribute of session cookies.
        SESSION_HTTPONLY (bool): The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing.
        SESSION_DOMAIN (bool): The Domain attribute of session cookies.
        SESSION_EXPIRES_ON_CLIENT: If checked: when session cookies expire, they are removed on the client’s browser.
        SESSION_ENCODING_ALGORITHM (str): The algorithm used to encode sessions to a JWT.
        SESSION_PREFIX (str): Prefix attached to the beginning of session cookies.
        CAPTCHA_SESSION_EXPIRATION (int): The amount of seconds till captcha session expiration on creation.
        CAPTCHA_FONT (str): The file path to the font being used for captcha generation.
        TWO_STEP_SESSION_EXPIRATION (int):  The amount of seconds till two step session expiration on creation
        AUTHENTICATION_SESSION_EXPIRATION (bool): The amount of seconds till authentication session expiration on creation.
        ALLOW_LOGIN_WITH_USERNAME (bool): Allows login via username and email.
        DATABASE_URL (str): Database URL for connecting to the database Sanic Security will use. Intended to prevent the database url from being hardcoded.
    """

    SECRET: str
    CACHE: str
    SESSION_SAMESITE: str
    SESSION_SECURE: bool
    SESSION_HTTPONLY: bool
    SESSION_DOMAIN: str
    SESSION_EXPIRES_ON_CLIENT: bool
    SESSION_ENCODING_ALGORITHM: str
    SESSION_PREFIX: str
    CAPTCHA_SESSION_EXPIRATION: int
    CAPTCHA_FONT: str
    TWO_STEP_SESSION_EXPIRATION: int
    AUTHENTICATION_SESSION_EXPIRATION: int
    ALLOW_LOGIN_WITH_USERNAME: bool
    DATABASE_URL: str

    def load_environment_variables(self, load_env="SANIC_SECURITY_"):
        """
        Any environment variables defined with the prefix argument will be applied to the config.

        Args:
            load_env (str):  Prefix being used to apply environment variables into the config.
        """

        for key, value in environ.items():
            if not key.startswith(load_env):
                continue

            _, config_key = key.split(load_env, 1)

            for converter in (int, float, str_to_bool, str):
                try:
                    self[config_key] = converter(value)
                    break
                except ValueError:
                    pass

    def __init__(self):
        super().__init__(DEFAULT_CONFIG)
        self.__dict__ = self
        self.load_environment_variables()


config = Config()
