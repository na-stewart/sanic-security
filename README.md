[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Downloads](https://static.pepy.tech/badge/sanic-security)](https://pepy.tech/project/sanic-security)
[![Conda Downloads](https://img.shields.io/conda/dn/conda-forge/sanic-security.svg)](https://anaconda.org/conda-forge/sanic-security)


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">Sanic Security</h3>
  <p align="center">
   An async security library for the Sanic framework.
  </p>
</p>


<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Configuration](#configuration)
* [Usage](#usage)
    * [OAuth](#oauth)
    * [Authentication](#authentication)
    * [CAPTCHA](#captcha)
    * [Two-step Verification](#two-step-verification)
    * [Authorization](#authorization)
    * [Testing](#testing)
    * [Tortoise](#tortoise)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#versioning)
* [Support](https://discord.gg/JHpZkMfKTJ)

<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication, authorization, and verification library designed for use with the 
[Sanic](https://github.com/huge-success/sanic) web app framework.

* OAuth2 integration
* Login, registration, and authentication with refresh mechanisms
* Role based authorization with wildcard permissions
* Image & audio CAPTCHA
* Two-step verification
* Logging & auditing

Visit [security.na-stewart.com](https://security.na-stewart.com) for documentation.

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install [PyPI](https://pypi.org/) (likely included with your Python build).

### Installation

* Install the Sanic Security package.
```shell
pip3 install sanic-security
````

* Install the Sanic Security package with the [cryptography](https://github.com/pyca/cryptography) dependency included.

If you're planning on encoding or decoding JWTs using certain digital signature algorithms (like RSA or ECDSA which use 
the public secret and private secret), you will need to install the `cryptography` library. This can be installed explicitly, or 
as an extra requirement.

```shell
pip3 install sanic-security[crypto]
````

* Install the Sanic Security package with the [httpx-oauth](https://github.com/frankie567/httpx-oauth) dependency included.

If you're planning on utilizing OAuth, you will need to install the `httpx-oauth` library. This can be installed explicitly, or 
as an extra requirement.

```shell
pip3 install sanic-security[oauth]
````

* Update Sanic Security if already installed.

```shell
pip3 install sanic-security --upgrade
```

### Configuration

Sanic Security configuration is merely a `SimpleNamespace` that can be modified using dot-notation.
For example: 

```python
from sanic_security.configuration import config as security_config

security_config.SECRET = "This is a big secret. Shhhhh"
security_config.CAPTCHA_FONT = "resources/captcha-font.ttf"
```

Any environment variables defined with the SANIC_SECURITY_ prefix will be applied to the config. For example, setting 
SANIC_SECURITY_SECRET will be loaded by the application automatically and fed into the SECRET config variable.

You can load environment variables with a different prefix via `security_config.load_environment_variables("NEW_PREFIX_")` method.

* Default configuration values:

| Key                                   | Value                        | Description                                                                                                                       |
|---------------------------------------|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **SECRET**                            | This is a big secret. Shhhhh | The secret used for generating and signing JWTs. This should be a string unique to your application. Keep it safe.                |
| **PUBLIC_SECRET**                     | None                         | The secret used for verifying and decoding JWTs and can be publicly shared. This should be a string unique to your application.   |
| **OAUTH_CLIENT**                      | None                         | The client ID provided by the OAuth provider, this is used to identify the application making the OAuth request.                  |
| **OAUTH_SECRET**                      | None                         | The client secret provided by the OAuth provider, this is used in conjunction with the client ID to authenticate the application. |
| **SESSION_SAMESITE**                  | Strict                       | The SameSite attribute of session cookies.                                                                                        |
| **SESSION_SECURE**                    | True                         | The Secure attribute of session cookies.                                                                                          |
| **SESSION_HTTPONLY**                  | True                         | The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing.  |
| **SESSION_DOMAIN**                    | None                         | The Domain attribute of session cookies.                                                                                          |
| **SESSION_ENCODING_ALGORITHM**        | HS256                        | The algorithm used to encode and decode session JWT's.                                                                            |
| **SESSION_PREFIX**                    | tkn                          | Prefix attached to the beginning of session cookies.                                                                              |
| **MAX_CHALLENGE_ATTEMPTS**            | 3                            | The maximum amount of session challenge attempts allowed.                                                                         |
| **CAPTCHA_SESSION_EXPIRATION**        | 180                          | The amount of seconds till captcha session expiration on creation. Setting to 0 will disable expiration.                          |
| **CAPTCHA_FONT**                      | captcha-font.ttf             | The file path to the font being used for captcha generation. Several fonts can be used by separating them via comma.              |
| **CAPTCHA_VOICE**                     | captcha-voice/               | The directory of the voice library being used for audio captcha generation.                                                       |
| **TWO_STEP_SESSION_EXPIRATION**       | 300                          | The amount of seconds till two-step session expiration on creation. Setting to 0 will disable expiration.                         |
| **AUTHENTICATION_SESSION_EXPIRATION** | 86400                        | The amount of seconds till authentication session expiration on creation. Setting to 0 will disable expiration.                   |
| **AUTHENTICATION_REFRESH_EXPIRATION** | 604800                       | The amount of seconds till authentication refresh expiration. Setting to 0 will disable refresh mechanism.                        |
| **ALLOW_LOGIN_WITH_USERNAME**         | False                        | Allows login via username; unique constraint is disabled when set to false.                                                       |
| **INITIAL_ADMIN_EMAIL**               | admin@example.com            | Email used when creating the initial admin account.                                                                               |
| **INITIAL_ADMIN_PASSWORD**            | admin123                     | Password used when creating the initial admin account.                                                                            |

## Usage

Sanic Security's authentication and verification functionality is session based. A new session will be created for the user after the user logs in or requests some form of verification (two-step, captcha). The session data is then encoded into a JWT and stored on a cookie on the user’s browser. The session cookie is then sent along with every subsequent request. The server can then compare the session stored on the cookie against the session information stored in the database to verify user’s identity and send a response with the corresponding state.

* Initialize Sanic Security as follows:
```python
initialize_security(app)
initialize_oauth(app)  # Remove if not utilizing OAuth
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
```

The tables in the below examples represent example [request form-data](https://sanicframework.org/en/guide/basics/request.html#form).

## OAuth

Provides users with a familiar experience by having them register/login using their existing credentials from other trusted services (such as Google, Discord, etc.).

This feature is designed to complement existing protocols by linking Sanic Security with the user's OAuth credentials. As a result, developers can leverage robust session handling and account management.

* Define OAuth clients

You can [utilize various OAuth clients](https://frankie567.github.io/httpx-oauth/reference/httpx_oauth.clients/) based on your needs or [customize one](https://frankie567.github.io/httpx-oauth/usage/).
ID and secret should be stored and referenced via configuration.

```python
discord_oauth = DiscordOAuth2(
    "1325594509043830895",
    "WNMYbkDJjGlC0ej60qM-50tC9mMy0EXa",
)
google_oauth = GoogleOAuth2(
    "480512993828-e2e9tqtl2b8or62hc4l7hpoh478s3ni1.apps.googleusercontent.com",
    "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",
)
```

* Redirect to authorization URL

```python
@app.route("api/security/oauth", methods=["GET", "POST"])
async def on_oauth_request(request):
    return redirect(
        await google_oauth.get_authorization_url(
            "http://localhost:8000/api/security/oauth/callback",
            scope=google_oauth.base_scopes,
        )
    )
```

* Handle OAuth callback

```python
@app.get("api/security/oauth/callback")
async def on_oauth_callback(request):
    token_info, authentication_session = await oauth_callback(
        request, google_oauth, "http://localhost:8000/api/security/oauth/callback"
    )
    response = json(
        "Authorization successful.",
        {"token_info": token_info, "auth_session": authentication_session.json},
    )
    oauth_encode(response, token_info)
    authentication_session.encode(response)
    return response
```

* Get access token 

```python
@app.get("api/security/oauth/token")
async def on_oauth_token(request):
    token_info = await decode_oauth(request, google_oauth)
    return json(
        "Access token retrieved.",
        token_info,
    )
```

* Requires access token (This method is not called directly and instead used as a decorator)

```python
@app.get("api/security/oauth/token")
@requires_oauth(google_oauth)
async def on_oauth_token(request):
    return json(
        "Access token retrieved.",
        request.ctx.oauth,
    )
```

## Authentication
  
* Registration (with two-step email verification)

Phone can be null or empty.

| Key          | Value               |
|--------------|---------------------|
| **username** | example             |
| **email**    | example@example.com |
| **phone**    | 19811354186         |
| **password** | examplepass         |

```python
@app.post("api/security/register")
async def on_register(request):
    account = await register(request)
    two_step_session = await request_two_step_verification(request, account)
    await email_code(
        account.email, two_step_session.code  # Code = 24KF19
    )  # Custom method for emailing verification code.
    response = json(
        "Registration successful! Email verification required.", account.json
    )
    two_step_session.encode(response)
    return response
```

* Verify Account

Verifies the client's account via two-step session code.

| Key      | Value  |
|----------|--------|
| **code** | 24KF19 |

```python
@app.put("api/security/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json("You have verified your account and may login!", two_step_session.json)
```

* Login (with two-step email verification)

Credentials are retrieved via header are constructed by first combining the username and the password with a colon 
(aladdin:opensesame), and then by encoding the resulting string in base64 (YWxhZGRpbjpvcGVuc2VzYW1l). 
Here is an example authorization header: `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`. 

If this isn't desired, you can pass credentials into the login method instead.

You can use a username as well as an email for login if `ALLOW_LOGIN_WITH_USERNAME` is true in the config.

```python
@app.post("api/security/login")
async def on_login(request):
    authentication_session = await login(request, require_second_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.bearer, "2fa"
    )
    await email_code(
        authentication_session.bearer.email, two_step_session.code  # Code = XGED2U
    )  # Custom method for emailing verification code.
    response = json(
        "Login successful! Two-factor authentication required.",
        authentication_session.json,
    )
    authentication_session.encode(response)
    two_step_session.encode(response)
    return response
```

* Fulfill Second Factor

Fulfills client authentication session's second factor requirement via two-step session code.

| Key      | Value  |
|----------|--------|
| **code** | XGED2U |

```python
@app.put("api/security/fulfill-2fa")
async def on_two_factor_authentication(request):
    authentication_session = await fulfill_second_factor(request)
    response = json(
        "Authentication session second-factor fulfilled! You are now authenticated.",
        authentication_session.json,
    )
    return response
```

* Anonymous Login

Simply create a new session and encode it.

```python
@app.post("api/security/login/anon")
async def on_anonymous_login(request):
    authentication_session = await AuthenticationSession.new(request)
    response = json(
        "Anonymous client now associated with session!", authentication_session.json
    )
    authentication_session.encode(response)
    return response
```

* Logout

```python
@app.post("api/security/logout")
async def on_logout(request):
    authentication_session = await logout(request)
    token_info = await oauth_revoke(
        request, google_oauth
    )  # Remove if not utilizing OAuth
    response = json(
        "Logout successful!",
        {"token_info": token_info, "auth_session": authentication_session.json},
    )
    return response
```

* Authenticate

```python
@app.post("api/security/auth")
async def on_authenticate(request):
    authentication_session = await authenticate(request)
    response = json(
        "You have been authenticated.",
        authentication_session.json,
    )
    return response
```

* Requires Authentication (this method is not called directly and instead used as a decorator)

```python
@app.post("api/security/auth")
@requires_authentication
async def on_authenticate(request):
    response = json("You have been authenticated.", request.ctx.session.json)
    return response
```

## CAPTCHA

Protects against spam and malicious activities by ensuring that only real humans can complete certain actions like 
submitting a form or creating an account. A font and voice library for CAPTCHA challenges is included in the repository, 
or you can download/create your own and specify its path in the configuration.

* Request CAPTCHA

```python
@app.get("api/security/captcha")
async def on_captcha_img_request(request):
    captcha_session = await CaptchaSession.new(request)
    response = raw(
        captcha_session.get_image(), content_type="image/jpeg"
    )  # Captcha: LJ0F3U
    captcha_session.encode(response)
    return response
```

* Request CAPTCHA Audio

```python
@app.get("api/security/captcha/audio")
async def on_captcha_audio_request(request):
    captcha_session = await CaptchaSession.decode(request)
    return raw(captcha_session.get_audio(), content_type="audio/mpeg")
```

* Attempt CAPTCHA

| Key         | Value  |
|-------------|--------|
| **captcha** | LJ0F3U |

```python
@app.post("api/security/captcha")
async def on_captcha(request):
    captcha_session = await captcha(request)
    return json("Captcha attempt successful!", captcha_session.json)
```

* Requires CAPTCHA (this method is not called directly and instead used as a decorator)

| Key         | Value  |
|-------------|--------|
| **captcha** | LJ0F3U |

```python
@app.post("api/security/captcha")
@requires_captcha
async def on_captcha(request):
    return json("Captcha attempt successful!", request.ctx.session.json)
```

## Two-step Verification

Two-step verification should be integrated with other custom functionalities, such as forgot password recovery.

* Request Two-step Verification

| Key         | Value               |
|-------------|---------------------|
| **email**   | example@example.com |

```python
@app.post("api/security/two-step/request")
async def on_two_step_request(request):
    two_step_session = await request_two_step_verification(request)  # Code = T2I58I
    await email_code(
        two_step_session.bearer.email, two_step_session.code
    )  # Custom method for emailing verification code.
    response = json("Verification request successful!", two_step_session.json)
    two_step_session.encode(response)
    return response
``` 

* Resend Two-step Verification Code

```python
@app.post("api/security/two-step/resend")
async def on_two_step_resend(request):
    two_step_session = await TwoStepSession.decode(request)  # Code = T2I58I
    await email_code(
        two_step_session.bearer.email, two_step_session.code
    )  # Custom method for emailing verification code.
    return json("Verification code resend successful!", two_step_session.json)
```

* Attempt Two-step Verification

| Key      | Value  |
|----------|--------|
| **code** | T2I58I |

```python
@app.post("api/security/two-step")
async def on_two_step_verification(request):
    two_step_session = await two_step_verification(request)
    response = json("Two-step verification attempt successful!", two_step_session.json)
    return response
```

* Requires Two-step Verification (this method is not called directly and instead used as a decorator)

| Key      | Value  |
|----------|--------|
| **code** | T2I58I |

```python
@app.post("api/security/two-step")
@requires_two_step_verification
async def on_two_step_verification(request):
    response = json(
        "Two-step verification attempt successful!", request.ctx.session.json
    )
    return response
```

## Authorization

Sanic Security uses role based authorization with wildcard permissions.

Roles are created for various job functions. The permissions to perform certain operations are assigned to specific roles. 
Users are assigned particular roles, and through those role assignments acquire the permissions needed to perform 
particular system functions. Since users are not assigned permissions directly, but only acquire them through their 
role (or roles), management of individual user rights becomes a matter of simply assigning appropriate roles to the 
user's account; this simplifies common operations, such as adding a user, or changing a user's department. 

Wildcard permissions support the concept of multiple levels or parts. For example, you could grant a user the permission
`printer:query`, `printer:query,delete`, or `printer:*`.

* Assign Role

```python
await assign_role(
    "Chat Room Moderator",
    account,
    "Can read and delete messages in all chat rooms, suspend and mute accounts, and control voice chat.",
    "channels:view,delete",
    "voice:*",
    "account:suspend,mute",
)
```

* Check Permissions

```python
@app.post("api/security/perms")
async def on_check_perms(request):
    authentication_session = await check_permissions(
        request, "channels:view", "voice:*"
    )
    return json("Account is authorized.", authentication_session.json)
```

* Require Permissions (this method is not called directly and instead used as a decorator.)

```python
@app.post("api/security/perms")
@requires_permission("channels:view", "voice:*")
async def on_check_perms(request):
    return json("Account is authorized.", request.ctx.session.json)
```

* Check Roles

```python
@app.post("api/security/roles")
async def on_check_roles(request):
    authentication_session = await check_roles(request, "Chat Room Moderator")
    return json("Account is authorized.", authentication_session.json)
```

* Require Roles (This method is not called directly and instead used as a decorator)

```python
@app.post("api/security/roles")
@requires_role("Chat Room Moderator")
async def on_check_roles(request):
    return json("Account is authorized.", request.ctx.session.json)
```

## Testing

* Set the `TEST_DATABASE_URL` configuration value.

* Make sure the test Sanic instance (`test/server.py`) is running on your machine.

* Run the test client (`test/tests.py`) for results.

## Tortoise

Sanic Security uses [Tortoise ORM](https://tortoise-orm.readthedocs.io/en/latest/index.html) for database operations.

Tortoise ORM is an easy-to-use asyncio ORM (Object Relational Mapper).

* Initialise your models and database like so: 

```python
async def init():
    await Tortoise.init(
        db_url="sqlite://db.sqlite3",
        modules={"models": ["sanic_security.models", "app.models"]},
    )
    await Tortoise.generate_schemas()
```

or

```python
register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["sanic_security.models", "app.models"]},
    generate_schemas=True,
)
```

* Define your models like so:

```python
from tortoise.models import Model
from tortoise import fields


class Tournament(Model):
    id = fields.IntField(pk=True)
    name = fields.TextField()
```

* Use it like so:

```python
# Create instance by save
tournament = Tournament(name="New Tournament")
await tournament.save()

# Or by .create()
await Tournament.create(name="Another Tournament")

# Now search for a record
tour = await Tournament.filter(name__contains="Another").first()
print(tour.name)
```

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- Versioning -->
## Versioning

**x.x.x**

* MAJOR version when you make incompatible API changes.

* MINOR version when you add functionality in a backwards compatible manner.

* PATCH version when you make backwards compatible bug fixes.

[https://semver.org/](https://semver.org/)
