import functools
import time
from typing import Literal, Union

import jwt
from httpx_oauth.oauth2 import BaseOAuth2, RefreshTokenError
from jwt import DecodeError
from sanic import Request, HTTPResponse, redirect, Sanic
from tortoise.exceptions import IntegrityError, DoesNotExist

from sanic_security.configuration import config
from sanic_security.exceptions import JWTDecodeError, ExpiredError, CredentialsError
from sanic_security.models import Account, AuthenticationSession

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


async def oauth_redirect(
    client: BaseOAuth2,
    redirect_uri: str = config.OAUTH_REDIRECT,
    scope: list[str] = None,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: Literal["plain", "S256"] = None,
    **extra_params: str,
) -> HTTPResponse:
    """
    Constructs the authorization URL and returns a redirect response to prompt the user to authorize the application.

    Args:
        client (BaseOAuth2): OAuth provider.
        redirect_uri (str): The URL where the user will be redirected after authorization.
        scope (list[str]): The scopes to be requested. If not provided, `base_scopes` will be used.
        state (str): An opaque value used by the client to maintain state between the request and the callback.
        code_challenge (str): [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)) code challenge.
        code_challenge_method (str) [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)) code challenge method.
        **extra_params (dict[str, str]): Optional extra parameters specific to the service.

    Returns:
        oauth_redirect
    """
    return redirect(
        await client.get_authorization_url(
            redirect_uri,
            state,
            scope,
            code_challenge,
            code_challenge_method,
            extra_params,
        )
    )


async def oauth_callback(
    request: Request,
    client: BaseOAuth2,
    redirect_uri: str = config.OAUTH_REDIRECT,
    code_verifier: str = None,
) -> tuple[dict, AuthenticationSession]:
    """
    Requests an access token using the authorization code obtained after the user has authorized the application.
    An account is retrieved if it already exists, created if it doesn't, and the user is logged in.

    Args:
        request (Request): Sanic request parameter.
        client (BaseOAuth2): OAuth provider.
        redirect_uri (str): The URL where the user was redirected after authorization.
        code_verifier (str): Optional code verifier used in the [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)) flow.

    Raises:
        CredentialsError
        GetAccessTokenError
        GetIdEmailError

    Returns:
        oauth_redirect
    """
    access_token = await client.get_access_token(
        request.args.get("code"),
        redirect_uri,
        code_verifier,
    )
    if "expires_at" not in access_token:
        access_token["expires_at"] = time.time() + access_token["expires_in"]
    oauth_id, email = await client.get_id_email(access_token["access_token"])
    try:
        account, _ = await Account.get_or_create(email=email, oauth_id=oauth_id)
        authentication_session = await AuthenticationSession.new(
            request,
            account,
        )
        return access_token, authentication_session
    except IntegrityError:
        raise CredentialsError(
            f"Account may not be linked to an OAuth provider if it already exists.", 409
        )
    except DoesNotExist:
        raise CredentialsError(
            "Account may already be linked to an OAuth provider.", 409
        )


def oauth_encode(
    response: HTTPResponse, client: Union[BaseOAuth2, str], access_token: dict
) -> None:
    """
    Transforms OAuth access token into JWT and then is stored in a cookie.

    Args:
        response (HTTPResponse): Sanic response used to store JWT into a cookie on the client.
        client (Union[BaseOAuth2, str]): OAuth provider.
        access_token (dict): OAuth access token.
    """
    response.cookies.add_cookie(
        f"{config.SESSION_PREFIX}_{(client if isinstance(client, str) else client.__class__.__name__)[:7].lower()}",
        str(
            jwt.encode(
                access_token,
                config.SECRET,
                config.SESSION_ENCODING_ALGORITHM,
            ),
        ),
        httponly=config.SESSION_HTTPONLY,
        samesite=config.SESSION_SAMESITE,
        secure=config.SESSION_SECURE,
        domain=config.SESSION_DOMAIN,
        max_age=access_token["expires_in"] + config.AUTHENTICATION_REFRESH_EXPIRATION,
    )


async def oauth_decode(request: Request, client: BaseOAuth2, refresh=False) -> dict:
    """
    Decodes OAuth JWT token from client cookie into an access token.

    Args:
        request (Request): Sanic request parameter.
        client (BaseOAuth2): OAuth provider.
        refresh (bool): Ensures that the decoded access token is refreshed.

    Raises:
        JWTDecodeError
        ExpiredError
        RefreshTokenNotSupportedError

    Returns:
        access_token

    """
    try:
        access_token = jwt.decode(
            request.cookies.get(
                f"{config.SESSION_PREFIX}_{client.__class__.__name__[:7].lower()}",
            ),
            config.PUBLIC_SECRET or config.SECRET,
            config.SESSION_ENCODING_ALGORITHM,
        )
        if time.time() > access_token["expires_at"] or refresh:
            access_token = await client.refresh_token(access_token["refresh_token"])
            access_token["is_refresh"] = True
            access_token["client"] = client.__class__.__name__
            if "expires_at" not in access_token:
                access_token["expires_at"] = time.time() + access_token["expires_in"]
        request.ctx.oauth = access_token
        return access_token
    except RefreshTokenError:
        raise ExpiredError
    except DecodeError:
        raise JWTDecodeError


def requires_oauth(client: BaseOAuth2):
    """
    Decodes OAuth JWT token from client cookie into an access token.

    Args:
        client (BaseOAuth2): OAuth provider.

    Example:
        This method is not called directly and instead used as a decorator:

            @app.post('api/oauth')
            @requires_oauth
            async def on_oauth(request):
                return text('OAuth access token retrieved!')

    Raises:
        JWTDecodeError
        ExpiredError
        RefreshTokenNotSupportedError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            await oauth_decode(request, client)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


def initialize_oauth(app: Sanic) -> None:
    """
    Attaches refresh encoder middleware.

    Args:
        app (Sanic): Sanic application instance.
    """

    @app.on_response
    async def refresh_encoder_middleware(request, response):
        if hasattr(request.ctx, "oauth") and getattr(
            request.ctx.oauth, "is_refresh", False
        ):
            oauth_encode(
                response,
                request.ctx.oauth["client"],
                request.ctx.oauth,
            )
