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
    "LOAD_ENV": "SANIC_SECURITY_"
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
        SESSION_EXPIRES_ON_CLIENT: If checked, session cookies expire on the client’s browser.
        SESSION_ENCODING_ALGORITHM (str): The algorithm used to encode sessions to JWT.
        SESSION_PREFIX (str): Prefix attached to the beginning ofs session cookies.
        CAPTCHA_SESSION_EXPIRATION (int): The amount of seconds till captcha session expiration.
        CAPTCHA_FONT (str): The file path to the font being used for captcha generation.
        TWO_STEP_SESSION_EXPIRATION (int):  The amount of seconds till two step session expiration.
        AUTHENTICATION_SESSION_EXPIRATION (bool): The amount of seconds till authentication session expiration.
        ALLOW_LOGIN_WITH_USERNAME (bool): Allows login via username and email.
        LOAD_ENV (str): Any environment variables defined with the LOAD_ENV prefix will be applied to the config.
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
    LOAD_ENV: str

    def load_env(self):




    def __init__(self):
        super().__init__(DEFAULT_CONFIG)
        self.__dict__ = self


config = Config()
