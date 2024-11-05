<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

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
    * [Authentication](#authentication)
    * [Captcha](#captcha)
    * [Two-Step Verification](#two-step-verification)
    * [Authorization](#authorization)
    * [Testing](#testing)
    * [Tortoise](#tortoise)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#versioning)
* [Support](https://discord.gg/JHpZkMfKTJ)

<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication, authorization, and verification library designed for use with [Sanic](https://github.com/huge-success/sanic).

* Login, registration, and authentication with refresh mechanisms
* Role based authorization with wildcard permissions
* Two-factor authentication
* Two-step verification
* Captcha
* Logging

Visit [security.na-stewart.com](https://security.na-stewart.com) for documentation.

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install [Pip](https://pypi.org/).

### Installation

* Install the Sanic Security pip package.
```shell
pip3 install sanic-security
````

* Install the Sanic Security pip package with the `cryptography` dependency included.

If you are planning on encoding or decoding JWTs using certain digital signature algorithms (like RSA or ECDSA which use 
the public secret and private secret), you will need to install the `cryptography` library. This can be installed explicitly, or 
as an extra requirement.

```shell
pip3 install sanic-security[crypto]
````

* For developers, fork Sanic Security and install development dependencies.
```shell
pip3 install -e ".[dev]"
````

* Update sanic-security if already installed.
```shell
pip3 install --upgrade sanic-security
```

### Configuration

Sanic Security configuration is merely an object that can be modified either using dot-notation or like a 
dictionary.

For example: 

```python
from sanic_security.configuration import config

config.SECRET = "This is a big secret. Shhhhh"
config["CAPTCHA_FONT"] = "./resources/captcha-font.ttf"
```

You can also use the update() method like on regular dictionaries.

Any environment variables defined with the SANIC_SECURITY_ prefix will be applied to the config. For example, setting 
SANIC_SECURITY_SECRET will be loaded by the application automatically and fed into the SECRET config variable.

You can load environment variables with a different prefix via `config.load_environment_variables("NEW_PREFIX_")` method.

* Default configuration values:

| Key                                   | Value                        | Description                                                                                                                      |
|---------------------------------------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| **SECRET**                            | This is a big secret. Shhhhh | The secret used for generating and signing JWTs. This should be a string unique to your application. Keep it safe.               |
| **PUBLIC_SECRET**                     | None                         | The secret used for verifying and decoding JWTs and can be publicly shared. This should be a string unique to your application.  |
| **SESSION_SAMESITE**                  | Strict                       | The SameSite attribute of session cookies.                                                                                       |
| **SESSION_SECURE**                    | True                         | The Secure attribute of session cookies.                                                                                         |
| **SESSION_HTTPONLY**                  | True                         | The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing. |
| **SESSION_DOMAIN**                    | None                         | The Domain attribute of session cookies.                                                                                         |
| **SESSION_ENCODING_ALGORITHM**        | HS256                        | The algorithm used to encode and decode session JWT's.                                                                           |
| **SESSION_PREFIX**                    | tkn                          | Prefix attached to the beginning of session cookies.                                                                             |
| **MAX_CHALLENGE_ATTEMPTS**            | 5                            | The maximum amount of session challenge attempts allowed.                                                                        |
| **CAPTCHA_SESSION_EXPIRATION**        | 60                           | The amount of seconds till captcha session expiration on creation. Setting to 0 will disable expiration.                         |
| **CAPTCHA_FONT**                      | captcha-font.ttf             | The file path to the font being used for captcha generation.                                                                     |
| **TWO_STEP_SESSION_EXPIRATION**       | 200                          | The amount of seconds till two-step session expiration on creation. Setting to 0 will disable expiration.                        |
| **AUTHENTICATION_SESSION_EXPIRATION** | 86400                        | The amount of seconds till authentication session expiration on creation. Setting to 0 will disable expiration.                  |
| **AUTHENTICATION_REFRESH_EXPIRATION** | 604800                       | The amount of seconds till authentication refresh expiration. Setting to 0 will disable refresh mechanism.                       |
| **ALLOW_LOGIN_WITH_USERNAME**         | False                        | Allows login via username and email.                                                                                             |
| **INITIAL_ADMIN_EMAIL**               | admin@example.com            | Email used when creating the initial admin account.                                                                              |
| **INITIAL_ADMIN_PASSWORD**            | admin123                     | Password used when creating the initial admin account.                                                                           |

## Usage

Sanic Security's authentication and verification functionality is session based. A new session will be created for the user after the user logs in or requests some form of verification (two-step, captcha). The session data is then encoded into a JWT and stored on a cookie on the user’s browser. The session cookie is then sent
along with every subsequent request. The server can then compare the session stored on the cookie against the session information stored in the database to verify user’s identity and send a response with the corresponding state.

* Initialize sanic-security as follows:
```python
initialize_security(app)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
```

The tables in the below examples represent example [request form-data](https://sanicframework.org/en/guide/basics/request.html#form).

## Authentication
  
* Registration (With two-step account verification)

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
        "Registration successful! Email verification required.",
        two_step_session.json,
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
@app.post("api/security/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json("You have verified your account and may login!", two_step_session.json)
```

* Login (With two-factor authentication)

Credentials are retrieved via header are constructed by first combining the username and the password with a colon 
(aladdin:opensesame), and then by encoding the resulting string in base64 (YWxhZGRpbjpvcGVuc2VzYW1l). 
Here is an example authorization header: `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`. You can use a username 
as well as an email for login if `ALLOW_LOGIN_WITH_USERNAME` is true in the config.

```python
@app.post("api/security/login")
async def on_login(request):
    authentication_session = await login(request, require_second_factor=True)
    two_step_session = await request_two_step_verification(
        request, authentication_session.bearer
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

If this isn't desired, you can pass an account and password attempt directly into the login method instead.

* Fulfill Second Factor

Fulfills client authentication session's second factor requirement via two-step session code.

| Key      | Value  |
|----------|--------|
| **code** | XGED2U |

```python
@app.post("api/security/fulfill-2fa")
async def on_two_factor_authentication(request):
    authentication_session = await fulfill_second_factor(request)
    response = json(
        "Authentication session second-factor fulfilled! You are now authenticated.",
        authentication_session.json,
    )
    authentication_session.encode(response)
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
    return json("Logout successful!", authentication_session.json)
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

* Requires Authentication (This method is not called directly and instead used as a decorator)

```python
@app.post("api/security/auth")
@requires_authentication
async def on_authenticate(request):
    authentication_session = request.ctx.authentication_session
    response = json(
        "You have been authenticated.",
        authentication_session.json,
    )
    return response
```

## Captcha

A pre-existing font for captcha challenges is included in the Sanic Security repository. You may set your own font by 
downloading a .ttf font and defining the file's path in the configuration.

[1001 Free Fonts](https://www.1001fonts.com/)

[Recommended Font](https://www.1001fonts.com/source-sans-pro-font.html)

* Request Captcha

```python
@app.get("api/security/captcha")
async def on_captcha_img_request(request):
    captcha_session = await request_captcha(request)
    response = captcha_session.get_image()  # Captcha: LJ0F3U
    captcha_session.encode(response)
    return response
```

* Captcha

| Key         | Value  |
|-------------|--------|
| **captcha** | LJ0F3U |

```python
@app.post("api/security/captcha")
async def on_captcha(request):
    captcha_session = await captcha(request)
    return json("Captcha attempt successful!", captcha_session.json)
```

* Requires Captcha (This method is not called directly and instead used as a decorator)

| Key         | Value  |
|-------------|--------|
| **captcha** | LJ0F3U |

```python
@app.post("api/security/captcha")
@requires_captcha
async def on_captcha(request):
    return json("Captcha attempt successful!", request.ctx.captcha_session.json)
```

## Two-step Verification

Two-step verification should be integrated with other custom functionality. For example, account verification during registration.

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

* Two-step Verification

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

* Requires Two-step Verification (This method is not called directly and instead used as a decorator)

| Key      | Value  |
|----------|--------|
| **code** | T2I58I |

```python
@app.post("api/security/two-step")
@requires_two_step_verification
async def on_two_step_verification(request):
    response = json(
        "Two-step verification attempt successful!",
        request.ctx.two_step_session.json,
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
    "channels:view,delete, account:suspend,mute, voice:*",
    "Can read and delete messages in all chat rooms, suspend and mute accounts, and control voice chat.",
)
```

* Check Permissions

```python
@app.post("api/security/perms")
async def on_check_perms(request):
    authentication_session = await check_permissions(
        request, "channels:view", "voice:*"
    )
    return text("Account is authorized.")
```

* Require Permissions (This method is not called directly and instead used as a decorator.)

```python
@app.post("api/security/perms")
@require_permissions("channels:view", "voice:*")
async def on_check_perms(request):
    return text("Account is authorized.")
```

* Check Roles

```python
@app.post("api/security/roles")
async def on_check_roles(request):
    authentication_session = await check_roles(request, "Chat Room Moderator")
    return text("Account is authorized.")
```

* Require Roles (This method is not called directly and instead used as a decorator)

```python
@app.post("api/security/roles")
@require_roles("Chat Room Moderator")
async def on_check_roles(request):
    return text("Account is authorized.")
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

Distributed under the MIT License. See `LICENSE` for more information.

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
