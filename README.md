<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Downloads](https://pepy.tech/badge/sanic-security)](https://pepy.tech/project/sanic-security)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Conda](https://anaconda.org/conda-forge/sanic-security/badges/installer/conda.svg)](https://anaconda.org/conda-forge/sanic-security)
[![Conda Downloads](https://anaconda.org/conda-forge/sanic-security/badges/downloads.svg)](https://anaconda.org/conda-forge/sanic-security)


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">Sanic Security</h3>
  <p align="center">
   An effective, simple, and async security library for the Sanic framework.
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
    * [Authentication](#authentication)
    * [Captcha](#captcha)
    * [Two Step Verification](#two-step-verification)
    * [Authorization](#authorization)
    * [Testing](#testing)
    * [Tortoise](#tortoise)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#Versioning)


<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication, authorization, and verification library designed for use with [Sanic](https://github.com/huge-success/sanic).
This library contains a variety of features including:

* Login, registration, and authentication (including access/refresh tokens)
* Two-factor authentication
* Two-step verification
* Captcha
* Role based authorization with wildcard permissions

This repository has been starred by Sanic's core maintainer:

[![aphopkins](https://github.com/sunset-developer/sanic-security/blob/main/images/ahopkins.png)](https://github.com/ahopkins)

Please visit [security.sunsetdeveloper.com](https://security.sunsetdeveloper.com) for documentation.

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install pip.

### Prerequisites

* pip
```shell
sudo apt-get install python3-pip
```

### Installation

* Install the Sanic Security pip package.
```shell
pip3 install sanic-security
````

* Install the Sanic Security pip package with the `cryptography` dependency included.

If you are planning on encoding or decoding JWTs using certain digital signature algorithms (like RSA or ECDSA which use 
the public secret and private secret), you will need to install the `cryptography` library. This can be installed explicitly, or 
as a required extra in the `sanic-security` requirement.

```shell
pip3 install sanic-security[crypto]
````

* For developers, fork Sanic Security and install development dependencies.
```shell
pip3 install -e ".[dev]"
````

### Configuration

Sanic Security configuration is merely an object that can be modified either using dot-notation or like a 
dictionary.

For example: 

```python
from sanic_security.configuration import config

config.SECRET = "This is a big secret. Shhhhh"
config["CAPTCHA_FONT"] = "./resources/captcha.ttf"
```

You can also use the update() method like on regular dictionaries.

Any environment variables defined with the SANIC_SECURITY_ prefix will be applied to the config. For example, setting 
SANIC_SECURITY_SECRET will be loaded by the application automatically and fed into the SECRET config variable.

You can load environment variables with a different prefix via calling the `config.load_environment_variables("NEW_PREFIX_")` method.

* Default configuration values:

Key | Value | Description |
--- | --- |  --- |
**SECRET** | This is a big secret. Shhhhh | The secret used for generating and signing JWTs. This should be a string unique to your application. Keep it safe.
**PUBLIC_SECRET** | None | The secret used for verifying and decoding JWTs and can be publicly shared. This should be a string unique to your application.
**CACHE** | ./security-cache | The path used for caching.
**SESSION_SAMESITE** | strict | The SameSite attribute of session cookies.
**SESSION_SECURE** | False | The Secure attribute of session cookies.
**SESSION_HTTPONLY** | True | The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing.
**SESSION_DOMAIN** | None | The Domain attribute of session cookies.
**SESSION_EXPIRES_ON_CLIENT** | False | When true, session cookies are removed from the clients browser when the session expires.
**SESSION_ENCODING_ALGORITHM** | HS256 | The algorithm used to encode and decode session JWTs.
**SESSION_PREFIX** | token | Prefix attached to the beginning of session cookies.
**MAX_CHALLENGE_ATTEMPTS** | 5 | The maximum amount of session challenge attempts allowed.
**CAPTCHA_SESSION_EXPIRATION** | 60 | The amount of seconds till captcha session expiration on creation. Setting to 0 will disable expiration.
**CAPTCHA_FONT** | captcha.ttf | The file path to the font being used for captcha generation.
**TWO_STEP_SESSION_EXPIRATION** | 200 | The amount of seconds till two step session expiration on creation. Setting to 0 will disable expiration.
**AUTHENTICATION_SESSION_EXPIRATION** | 2692000 | The amount of seconds till authentication session expiration on creation. Setting to 0 will disable expiration.
**ALLOW_LOGIN_WITH_USERNAME** | False | Allows login via username and email.
**INITIAL_ADMIN_EMAIL** | admin@example.com | Email used when creating the initial admin account.
**INITIAL_ADMIN_PASSWORD** | admin123 | Password used when creating the initial admin account.
**TEST_DATABASE_URL** | sqlite://:memory: | Database URL for connecting to the database Sanic Security will use for testing.

## Usage

Sanic Security's authentication and verification functionality is session based.

A new session will be created for the user after the user logs in or requests some form of verification (two-step, captcha).
The session data is then encoded into a JWT and stored on a cookie on the user’s browser. The session cookie would be sent
along with every subsequent request. The server can then compare the session stored on the cookie
against the session information stored in the database to verify user’s identity and send a response with the corresponding state.

The tables in the below examples represent example request `form-data` (https://sanicframework.org/en/guide/basics/request.html#form).

You can create the initial administrator account via the example below. This account can be logged into and has complete authoritative access.

```python
create_initial_admin_account(app)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
```

## Authentication

* Registration

Phone can be null or empty.

Key | Value |
--- | --- |
**username** | example 
**email** | example@example.com 
**phone** | 19811354186
**password** | testpass
**captcha** | Aj8HgD

```python
@app.post("api/auth/register")
@requires_captcha()
async def on_register(request, captcha_session):
    account = await register(request)
    two_step_session = await request_two_step_verification(request, account)
    await email_code(
        two_step_session.code
    )  # Custom method for emailing verification code.
    response = json("Registration successful!", two_step_session.bearer.json())
    two_step_session.encode(response)
    return response
```

* Verify Account

Key | Value |
--- | --- |
**code** | 192871

```python
@app.post("api/auth/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json(
        "You have verified your account and may login!", two_step_session.bearer.json()
    )
```

* Login

Login credentials are retrieved via the Authorization header. Credentials are constructed by first combining the 
username and the password with a colon (aladdin:opensesame), and then by encoding the resulting string in base64 
(YWxhZGRpbjpvcGVuc2VzYW1l). Here is an example authorization header: `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`.

You can use a username as well as an email for login if `ALLOW_LOGIN_WITH_USERNAME` is true in the config.

```python
@app.post("api/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.bearer.json())
    authentication_session.encode(response)
    return response
```

* Login (With two-factor authentication)

```python
@app.post("api/auth/login")
async def on_two_factor_login(request):
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.bearer
    )
    await email_code(
        two_step_session.code
    )  # Custom method for emailing verification code.
    response = json(
        "Login successful! A second factor is now required to be authenticated.",
        authentication_session.bearer.json(),
    )
    authentication_session.encode(response)
    two_step_session.encode(response)
    return response
```

* Second Factor

Key | Value |
--- | --- |
**code** | 192871

```python
@app.post("api/auth/login/second-factor")
@requires_two_step_verification()
async def on_login_second_factor(request, two_step_session):
    authentication_session = await on_second_factor(request)
    response = json(
        "Second factor attempt successful! You may now be authenticated!",
        authentication_session.bearer.json(),
    )
    return response
```

* Logout

```python
@app.post("api/auth/logout")
@requires_authentication()
async def on_logout(request, authentication_session):
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.bearer.json())
    return response
```

* Refresh Authentication

A refresh token is used that lets the client retrieve a new authentication session without having to ask the user to log in again.

```python
@app.post("api/auth/refresh")
async def on_refresh(request):
    refreshed_authentication_session = await refresh_authentication(request)
    response = json(
        "Authentication session refreshed!",
        refreshed_authentication_session.bearer.json(),
    )
    refreshed_authentication_session.encode(response)
    return response
```

* Requires Authentication

```python
@app.post("api/auth")
@requires_authentication()
async def on_authenticated(request, authentication_session):
    return json(
        f"Hello {authentication_session.bearer.username}! You have been authenticated.",
        authentication_session.bearer.json(),
    )
```

## Captcha

A pre-existing font for captcha challenges is included in the sanic-security repository. You may set your own font by 
downloading a .ttf font and defining the file's path in the configuration.

[1001 Free Fonts](https://www.1001fonts.com/)

[Recommended Font](https://www.1001fonts.com/source-sans-pro-font.html)

Captcha challenge example:

[![Captcha image.](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)

* Request Captcha

```python
@app.get("api/captcha")
async def on_request_captcha(request):
    captcha_session = await request_captcha(request)
    response = await captcha_session.get_image()
    captcha_session.encode(response)
    return response
```

* Requires Captcha

Key | Value |
--- | --- |
**captcha** | Aj8HgD

```python
@app.post("api/captcha")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    return json("Captcha attempt successful!", captcha_session.json())
```

## Two-step Verification

* Request Two-step Verification

Key | Value |
--- | --- |
**email** | example@example.com
**captcha** | Aj8HgD

```python
@app.post("api/verification/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    two_step_session = await request_two_step_verification(request)
    await email_code(
        two_step_session.code
    )  # Custom method for emailing verification code.
    response = json("Verification request successful!", two_step_session.bearer.json())
    two_step_session.encode(response)
    return response
```

* Resend Two-step Verification Code

```python
@app.post("api/verification/resend")
async def on_resend_verification(request):
    two_step_session = await TwoStepSession.decode(request)
    await email_code(
        two_step_session.code
    )  # Custom method for emailing verification code.
    return json("Verification code resend successful!", two_step_session.bearer.json())
```

* Requires Two-step Verification

Key | Value |
--- | --- |
**code** | 192871

```python
@app.post("api/verification")
@requires_two_step_verification()
async def on_verification(request, two_step_session):
    response = json(
        "Two-step verification attempt successful!", two_step_session.bearer.json()
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
`printer:query`, `printer:query,delete`, or `printer:*`. Inspired by [Apache Shiro](https://shiro.apache.org/permissions.html#multiple-parts).
* Assign Role

```python
await assign_role(
    "Chat Room Moderator",
    "Can read and delete messages in all chat rooms, suspend and mute accounts, and control voice chat.",
    "channels:view,delete, account:suspend,mute, voice:*",
    account,
)
```

* Require Permissions

```python
@app.post("api/channel/view")
@require_permissions("channels:view", "voice:*")
async def on_voice_chat_control(request, authentication_session):
    return text("Voice chat is now being controlled.")
```

* Require Roles

```python
@app.post("api/account/suspend")
@require_roles("Chat Room Moderator")
async def on_suspend_account(request, authentication_session):
    return text("Account successfully suspended.")
```

## Testing

* Set the `TEST_DATABASE_URL` configuration value.

* Make sure the test Sanic instance (`test/server.py`) is running on your machine.

* Run the unit test client (`test/tests.py`) for results.

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

Distributed under the GNU Affero General Public License v3.0. See `LICENSE` for more information.

<!-- Versioning -->
## Versioning

**0.0.0**

* MAJOR version when you make incompatible API changes.

* MINOR version when you add functionality in a backwards compatible manner.

* PATCH version when you make backwards compatible bug fixes.

[https://semver.org/](https://semver.org/)

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/sunset-developer/sanic-security.svg?style=flat-square
[contributors-url]: https://github.com/sunset-developer/sanic-security/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/sunset-developer/sanic-security.svg?style=flat-square
[forks-url]: https://github.com/sunset-developer/sanic-security/network/members
[stars-shield]: https://img.shields.io/github/stars/sunset-developer/sanic-security.svg?style=flat-square
[stars-url]: https://github.com/sunset-developer/sanic-security/stargazers
[issues-shield]: https://img.shields.io/github/issues/sunset-developer/sanic-security.svg?style=flat-square
[issues-url]: https://github.com/sunset-developer/sanic-security/issues
[license-shield]: https://img.shields.io/github/license/sunset-developer/sanic-security.svg?style=flat-square
[license-url]: https://github.com/sunset-developer/sanic-security/blob/master/LICENSE
