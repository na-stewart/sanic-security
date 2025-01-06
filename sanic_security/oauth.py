import time

import jwt
from httpx_oauth.oauth2 import BaseOAuth2
from sanic import Request, HTTPResponse, redirect, Sanic

from sanic_security.configuration import config

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

oauth_clients: dict[str, BaseOAuth2]


async def oauth(
    client: BaseOAuth2, redirect_uri: str = config.OAUTH_REDIRECT, **kwargs
) -> HTTPResponse:
    return redirect(await client.get_authorization_url(redirect_uri, **kwargs))


async def oauth_callback(
    request: Request,
    client: BaseOAuth2,
    redirect_uri: str = config.OAUTH_REDIRECT,
    code_verifier: str = None,
) -> dict:
    token_info = await client.get_access_token(
        request.args.get("code"),
        redirect_uri,
        code_verifier,
    )
    if "expires_at" not in token_info:
        token_info["expires_at"] = time.time() + token_info["expires_in"]
    return token_info


def oauth_encode(response: HTTPResponse, token_info: dict) -> None:
    response.cookies.add_cookie(
        f"{config.SESSION_PREFIX}_oauth",
        str(
            jwt.encode(
                token_info,
                config.SECRET,
                config.SESSION_ENCODING_ALGORITHM,
            ),
        ),
        httponly=config.SESSION_HTTPONLY,
        samesite=config.SESSION_SAMESITE,
        secure=config.SESSION_SECURE,
        domain=config.SESSION_DOMAIN,
        max_age=token_info["expires_in"] + config.AUTHENTICATION_REFRESH_EXPIRATION,
    )


async def get_oauth(request: Request, client: BaseOAuth2) -> dict:
    token_info = jwt.decode(
        request.cookies.get(
            f"{config.SESSION_PREFIX}_oauth",
        ),
        config.PUBLIC_SECRET or config.SECRET,
        config.SESSION_ENCODING_ALGORITHM,
    )
    if time.time() > token_info["expires_at"]:
        token_info = await client.refresh_token(token_info["refresh_token"])
        token_info["is_refresh"] = True
        if "expires_at" not in token_info:
            token_info["expires_at"] = time.time() + token_info["expires_in"]
    request.ctx.oauth = token_info
    return token_info


def initialize_oauth(app: Sanic) -> None:
    @app.on_response
    async def refresh_encoder_middleware(request, response):
        if hasattr(request.ctx, "oauth") and getattr(
            request.ctx.o_auth, "is_refresh", False
        ):
            oauth_encode(response, request.ctx.o_auth)
