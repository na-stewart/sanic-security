from os import environ

from sanic.utils import str_to_bool


"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2021 Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


DEFAULT_CONFIG = {
    "SECRET": "This is a big secret. Shhhhh",
    "PUBLIC_SECRET": None,
    "CACHE": "./security-cache",
    "SESSION_SAMESITE": "strict",
    "SESSION_SECURE": False,
    "SESSION_HTTPONLY": True,
    "SESSION_DOMAIN": None,
    "SESSION_EXPIRES_ON_CLIENT": False,
    "SESSION_PREFIX": "token",
    "SESSION_ENCODING_ALGORITHM": "HS256",
    "MAX_CHALLENGE_ATTEMPTS": 5,
    "CAPTCHA_SESSION_EXPIRATION": 60,
    "CAPTCHA_FONT": "captcha.ttf",
    "TWO_STEP_SESSION_EXPIRATION": 200,
    "AUTHENTICATION_SESSION_EXPIRATION": 2592000,
    "AUTHENTICATION_SESSION_REFRESH": True,
    "ALLOW_LOGIN_WITH_USERNAME": False,
    "INITIAL_ADMIN_EMAIL": "admin@example.com",
    "INITIAL_ADMIN_PASSWORD": "admin123",
    "TEST_DATABASE_URL": "sqlite://:memory:",
}


class Config(dict):
    """
    Sanic Security configuration.

    Attributes:
        SECRET (str): The secret used by the hashing algorithm for generating and signing JWTs. This should be a string unique to your application. Keep it safe.
        PUBLIC_SECRET (str): The secret used for verifying and decoding JWTs and can be publicly shared. This should be a string unique to your application.
        CACHE (str): The path used for caching.
        SESSION_SAMESITE (str): The SameSite attribute of session cookies.
        SESSION_SECURE (bool): The Secure attribute of session cookies.
        SESSION_HTTPONLY (bool): The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing.
        SESSION_DOMAIN (bool): The Domain attribute of session cookies.
        SESSION_EXPIRES_ON_CLIENT: When true, session cookies are removed from the clients browser when the session expires.
        SESSION_ENCODING_ALGORITHM (str): The algorithm used to encode sessions to a JWT.
        SESSION_PREFIX (str): Prefix attached to the beginning of session cookies.
        MAX_CHALLENGE_ATTEMPTS (str): The maximum amount of session challenge attempts allowed.
        CAPTCHA_SESSION_EXPIRATION (int): The amount of seconds till captcha session expiration on creation. Setting to 0 will disable expiration.
        CAPTCHA_FONT (str): The file path to the font being used for captcha generation.
        TWO_STEP_SESSION_EXPIRATION (int):  The amount of seconds till two step session expiration on creation. Setting to 0 will disable expiration.
        AUTHENTICATION_SESSION_EXPIRATION (bool): The amount of seconds till authentication session expiration on creation. Setting to 0 will disable expiration.
        AUTHENTICATION_SESSION_REFRESH (bool): A refresh token can be used to generate a new session instead of reauthenticating.
        ALLOW_LOGIN_WITH_USERNAME (bool): Allows login via username and email.
        INITIAL_ADMIN_EMAIL (str): Email used when generating the initial admin account.
        INITIAL_ADMIN_PASSWORD (str) Password used when generating the initial admin account.
        TEST_DATABASE_URL (str): Database URL for connecting to the database Sanic Security will use for testing
    """

    SECRET: str
    PUBLIC_SECRET: str
    CACHE: str
    SESSION_SAMESITE: str
    SESSION_SECURE: bool
    SESSION_HTTPONLY: bool
    SESSION_DOMAIN: str
    SESSION_EXPIRES_ON_CLIENT: bool
    SESSION_ENCODING_ALGORITHM: str
    SESSION_PREFIX: str
    MAX_CHALLENGE_ATTEMPTS: int
    CAPTCHA_SESSION_EXPIRATION: int
    CAPTCHA_FONT: str
    TWO_STEP_SESSION_EXPIRATION: int
    AUTHENTICATION_SESSION_EXPIRATION: int
    AUTHENTICATION_SESSION_REFRESH: bool
    ALLOW_LOGIN_WITH_USERNAME: bool
    INITIAL_ADMIN_EMAIL: str
    INITIAL_ADMIN_PASSWORD: str
    TEST_DATABASE_URL: str

    def load_environment_variables(self, load_env="SANIC_SECURITY_") -> None:
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
