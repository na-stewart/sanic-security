"""
Copyright (c) 2020-present Nicholas Aidan Stewart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import datetime

import jwt
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token
from sanic import Sanic, Request, HTTPResponse

from sanic_security.configuration import config

clients: [BaseOAuth2]


async def oauth(redirect_uri, *scope: str):
    authorization_url = await get_client().get_authorization_url(
        redirect_uri
        scope=scope
    )
    return authorization_url


async def oauth_callback(request: Request) -> HTTPResponse:
    token_info = await get_client().get_access_token(
        request.args.get("code"),
        "https://www.vitapath.io/api/v1/security/oauth/callback",
    )


def encode_token_info(response: HTTPResponse, token_info: OAuth2Token, client: str):
    response.cookies.add_cookie(
        f"{config.SESSION_PREFIX}_{client.lower()[:7]}",
        str(
            jwt.encode(
                token_info, config.SECRET, algorithm=config.SESSION_ENCODING_ALGORITHM
            ),
        ),
        httponly=config.SESSION_HTTPONLY,
        samesite=config.SESSION_SAMESITE,
        secure=config.SESSION_SECURE,
        domain=config.SESSION_DOMAIN,
        expires=token_info["expires_at"]
                + datetime.timedelta(seconds=config.AUTHENTICATION_REFRESH_EXPIRATION),
    )
    return response


def decode_token_info(request: Request, token_info: OAuth2Token, client: str):
    request.ctx.o_auth = jwt.decode(
        request.cookies.get(
            f"{config.SESSION_PREFIX}_{client.lower()[:7]}",
        ),
        config.PUBLIC_SECRET or config.SECRET,
        config.SESSION_ENCODING_ALGORITHM,
    )


def get_client() -> BaseOAuth2:
    pass


def initialize_oauth(app: Sanic, *oauth_clients: BaseOAuth2) -> None:
    global clients
    clients = oauth_clients

    @app.on_request
    async def token_acquisition_middleware(request):
        if request.cookies.get("oauth_fitbit"):
            request.ctx.o_auth = jwt.decode(
                request.cookies.get("oauth_fitbit"),
                security_config.SECRET,
                algorithms=["HS256"],
            )
            if time.time() > request.ctx.o_auth["expires_at"]:
                request.ctx.o_auth = await o_auth.refresh_token(
                    request.ctx.o_auth["refresh_token"]
                )
                request.ctx.o_auth["is_refresh"] = True

    @app.on_response
    async def refresh_encoder_middleware(request, response):
        if hasattr(request.ctx, "oauth") and getattr(
                request.ctx.oauth, "is_refresh", False
        ):
            response.cookies.add_cookie(
                "oauth_fitbit",
                jwt.encode(
                    request.ctx.o_auth, security_config.SECRET, algorithm="HS256"
                ),
                httponly=True,
            )
