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
from difflib import get_close_matches

import jwt
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token
from sanic import Sanic, Request, HTTPResponse

from sanic_security.configuration import config
from sanic_security.utils import is_expired

clients: dict[str, BaseOAuth2]


async def oauth(client: str, scopes: list[str], **kwargs) -> str:
    authorization_url = await get_client(client).get_authorization_url(
        config.OAUTH_REDIRECT, scope=scopes, extras_params=kwargs
    )
    return authorization_url


async def oauth_callback(request: Request, client: str) -> dict:
    token_info = await get_client(client).get_access_token(
        request.args.get("code"),
        "https://www.vitapath.io/api/v1/security/oauth/callback",
    )
    return token_info


def encode(response: HTTPResponse, token_info: OAuth2Token) -> None:
    response.cookies.add_cookie(
        f"{config.SESSION_PREFIX}_oauth",
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


def decode(request: Request) -> dict:
    token_info = jwt.decode(
        request.cookies.get(
            f"{config.SESSION_PREFIX}_oauth",
        ),
        config.PUBLIC_SECRET or config.SECRET,
        config.SESSION_ENCODING_ALGORITHM,
    )
    request.ctx.oauth = token_info
    return token_info


async def refresh(request: Request, client: str) -> None:
    token_info = decode(request)
    if is_expired(token_info["expires_at"]):
        request.ctx.oauth = await get_client(client).refresh_token(
            request.ctx.o_auth["refresh_token"]
        )
        request.ctx.o_auth["is_refresh"] = True


def get_client(client: str) -> BaseOAuth2:
    closest_match = get_close_matches(client, clients.keys(), n=1)
    return clients[closest_match[0]] if closest_match else None


def initialize_oauth(app: Sanic, *oauth_clients: BaseOAuth2) -> None:
    global clients
    for client in oauth_clients:
        clients[client.__class__.__name__.lower()] = client
