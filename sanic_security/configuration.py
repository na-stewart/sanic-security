DEFAULT_CONFIG = {
    "SECRET": "This is a big secret. Shhhhh",
    "CACHE": "./resources/security-cache",
    "SESSION_SAMESITE": "strict",
    "SESSION_SECURE": False,
    "SESSION_HTTPONLY": True,
    "CAPTCHA_SESSION_EXPIRATION": 60,
    "CAPTCHA_FONT": "captcha.ttf",
    "TWO_STEP_SESSION_EXPIRATION": 200,
    "AUTHENTICATION_SESSION_EXPIRATION": 2592000,
    "TWO_FACTOR_OVERRIDE": False,
    "JWT_ENCODING_ALGORITHM": "HS256"

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
        CAPTCHA_SESSION_EXPIRATION (int): The amount of seconds till captcha session expiration.
        CAPTCHA_FONT (str): The file path to the font being used for captcha generation.
        TWO_STEP_SESSION_EXPIRATION (int):  The amount of seconds till two step session expiration.
        AUTHENTICATION_SESSION_EXPIRATION (bool): The amount of seconds till authentication session expiration.
        JWT_ENCODING_ALGORITHM (str): The algorithm used to encode sessions to JWT.
    """
    SECRET: str
    CACHE: str
    SESSION_SAMESITE: str
    SESSION_SECURE: bool
    SESSION_HTTPONLY: bool
    CAPTCHA_SESSION_EXPIRATION: int
    CAPTCHA_FONT: str
    TWO_STEP_SESSION_EXPIRATION: int
    AUTHENTICATION_SESSION_EXPIRATION: int
    JWT_ENCODING_ALGORITHM: str

    def __init__(self):
        super().__init__(DEFAULT_CONFIG)
        self.__dict__ = self


config = Config()
