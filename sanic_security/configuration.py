"""
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
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

DEFAULT_CONFIG = {
    "SECRET": "This is a big secret. Shhhhh",
    "CACHE": "./resources/security-cache",
    "SESSION_SAMESITE": "strict",
    "SESSION_SECURE": False,
    "SESSION_HTTPONLY": True,
    "SESSION_DOMAIN": "",
    "SESSION_ENCODING_ALGORITHM": "HS256",
    "SESSION_EXPIRES_ON_CLIENT": False,
    "CAPTCHA_SESSION_EXPIRATION": 60,
    "CAPTCHA_FONT": "captcha.ttf",
    "TWO_STEP_SESSION_EXPIRATION": 200,
    "AUTHENTICATION_SESSION_EXPIRATION": 2592000,
    "TWO_FACTOR_OVERRIDE": False,
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
    SESSION_DOMAIN: bool
    SESSION_EXPIRES_ON_CLIENT: bool
    SESSION_ENCODING_ALGORITHM: str
    CAPTCHA_SESSION_EXPIRATION: int
    CAPTCHA_FONT: str
    TWO_STEP_SESSION_EXPIRATION: int
    AUTHENTICATION_SESSION_EXPIRATION: int

    def __init__(self):
        super().__init__(DEFAULT_CONFIG)
        self.__dict__ = self


config = Config()
