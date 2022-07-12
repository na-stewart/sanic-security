<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Downloads](https://pepy.tech/badge/sanic-security)](https://pepy.tech/project/sanic-security)
[![Conda Downloads](https://img.shields.io/conda/dn/conda-forge/sanic-security.svg)](https://anaconda.org/conda-forge/sanic-security)


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
* [ORM Support](#orm-support)
    * [Tortoise](#tortoise)
    * [μMongo](#μmongo)
    * [Custom](#custom)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#versioning)
* [Support](https://discord.gg/JHpZkMfKTJ)

<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication, authorization, and verification library designed for use with [Sanic](https://github.com/huge-success/sanic).
This library contains a variety of features including:

* Login, registration, and authentication
* Two-step verification
* Captcha
* Role based authorization with wildcard permissions

Please visit [security.sunsetdeveloper.com](https://security.sunsetdeveloper.com) for documentation.

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install pip.

### Prerequisites

* python3
* [poetry](https://poetry.eustace.io/)

This package relies on [poetry](https://poetry.eustace.io/) for dependency management and packaging.

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

Additionally, you can load security variables in your main project configuration, by prefixing the variables with the SANIC_SECURITY_ prefix.

Order of presedence is: Environment > Sanic Config

* Default configuration values:

| Key                                   | Value                        | Description                                                                                                                      |
|---------------------------------------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| **SECRET**                            | This is a big secret. Shhhhh | The secret used for generating and signing JWTs. This should be a string unique to your application. Keep it safe.               |
| **PUBLIC_SECRET**                     | None                         | The secret used for verifying and decoding JWTs and can be publicly shared. This should be a string unique to your application.  |
| **SESSION_SAMESITE**                  | strict                       | The SameSite attribute of session cookies.                                                                                       |
| **SESSION_SECURE**                    | True                         | The Secure attribute of session cookies.                                                                                         |
| **SESSION_HTTPONLY**                  | True                         | The HttpOnly attribute of session cookies. HIGHLY recommended that you do not turn this off, unless you know what you are doing. |
| **SESSION_DOMAIN**                    | None                         | The Domain attribute of session cookies.                                                                                         |
| **SESSION_EXPIRES_ON_CLIENT**         | False                        | If true, session cookies are removed from the client's browser when the session expires.                                         |
| **SESSION_ENCODING_ALGORITHM**        | HS256                        | The algorithm used to encode and decode session JWT's.                                                                           |
| **SESSION_PREFIX**                    | token                        | Prefix attached to the beginning of session cookies.                                                                             |
| **MAX_CHALLENGE_ATTEMPTS**            | 5                            | The maximum amount of session challenge attempts allowed.                                                                        |
| **CAPTCHA_SESSION_EXPIRATION**        | 60                           | The amount of seconds till captcha session expiration on creation. Setting to 0 will disable expiration.                         |
| **CAPTCHA_FONT**                      | captcha.ttf                  | The file path to the font being used for captcha generation.                                                                     |
| **TWO_STEP_SESSION_EXPIRATION**       | 200                          | The amount of seconds till two step session expiration on creation. Setting to 0 will disable expiration.                        |
| **AUTHENTICATION_SESSION_EXPIRATION** | 2692000                      | The amount of seconds till authentication session expiration on creation. Setting to 0 will disable expiration.                  |
| **ALLOW_LOGIN_WITH_USERNAME**         | False                        | Allows login via username and email.                                                                                             |
| **INITIAL_ADMIN_EMAIL**               | admin@example.com            | Email used when creating the initial admin account.                                                                              |
| **INITIAL_ADMIN_PASSWORD**            | admin123                     | Password used when creating the initial admin account.                                                                           |
| **INITIAL_ADMIN_PHONE**               | 1231231234                   | Phone number used when creating the initial admin account.                                                                           |
| **SANIC_SECURITY_ORM**                |['tortoise','umongo','manual']| ORM Provider to use. If 'manual', needed objects must be provided to init.                                                                           |



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

Phone and Username can be null or empty, but if provided, must be unique.

| Key          | Value               |
|--------------|---------------------|
| **username** | example             |
| **email**    | example@example.com |
| **phone**    | 19811354186         |
| **password** | examplepass         |

```python
account = await register(request)
two_step_session = await request_two_step_verification(request, account)
await email_code(two_step_session.code)  # Custom method for emailing verification code.
response = json("Registration successful!", await two_step_session.json())
two_step_session.encode(response)
return response
```

* Verify Account

| Key      | Value  |
|----------|--------|
| **code** | AJ8HGD |

```python
two_step_session = await verify_account(request)
return json(
    "You have verified your account and may login!", await two_step_session.json()
)
```

* Login

Login credentials are retrieved via the Authorization header. Credentials are constructed by first combining the 
username and the password with a colon (aladdin:opensesame), and then by encoding the resulting string in base64 
(YWxhZGRpbjpvcGVuc2VzYW1l). Here is an example authorization header: `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`.

You can use a username as well as an email for login if `ALLOW_LOGIN_WITH_USERNAME` is true in the config.

```python
authentication_session = await login(request)
response = json("Login successful!", await authentication_session.json())
authentication_session.encode(response)
return response
```

* Logout

```python
authentication_session = await logout(request)
response = json("Logout successful!", await authentication_session.json())
return response
```

* Requires Authentication

```python
@app.post("api/auth")
@requires_authentication()
async def on_authenticate(request, authentication_session):
    return json(
        "You have been authenticated.",
        await authentication_session.json(),
    )
```

## Captcha

A pre-existing font for captcha challenges is included in the Sanic Security repository. You may set your own font by 
downloading a .ttf font and defining the file's path in the configuration.

[1001 Free Fonts](https://www.1001fonts.com/)

[Recommended Font](https://www.1001fonts.com/source-sans-pro-font.html)

Captcha challenge example:

[![Captcha image.](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)

* Request Captcha

```python
captcha_session = await request_captcha(request)
response = get_image()
captcha_session.encode(response)
return response
```

* Requires Captcha

| Key         | Value  |
|-------------|--------|
| **captcha** | AJ8HGD |

```python
@app.post("api/captcha")
@requires_captcha()
async def on_captcha(request, captcha_session):
    return json("Captcha attempt successful!", await captcha_session.json())
```

## Two-step Verification

* Request Two-step Verification

| Key         | Value               |
|-------------|---------------------|
| **email**   | example@example.com |

```python
two_step_session = await request_two_step_verification(request)
await email_code(two_step_session.code)  # Custom method for emailing verification code.
response = json("Verification request successful!", await two_step_session.json())
two_step_session.encode(response)
return response
```

* Resend Two-step Verification Code

```python
two_step_session = await TwoStepSession.decode(request)
await email_code(two_step_session.code)  # Custom method for emailing verification code.
return json("Verification code resend successful!", await two_step_session.json())
```

* Requires Two-step Verification

| Key      | Value  |
|----------|--------|
| **code** | AJ8HGD |

```python
@app.post("api/verify")
@requires_two_step_verification()
async def on_verify(request, two_step_session):
    response = json(
        "Two-step verification attempt successful!", await two_step_session.json()
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

* Require Permissions

```python
@app.post("api/channel/voice/control")
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

* Set the `TEST_DATABASE_URL` configuration value, if you want to use an alternate URL than a mock instance.

* Execute the tests with `pytest`, under `Poetry`: `poetry run pytest -x`

## ORM Support
Sanic Security can either use the built-in Tortoise or μMongo models and ORMs, or allows you to provide your own at `init` time, which can be used instead.

### Tortoise
Sanic Security can use [Tortoise ORM](https://tortoise-orm.readthedocs.io/en/latest/index.html) for database operations. It is currently the default, unless you specify otherwise, and requires installation.

Tortoise ORM is an easy-to-use asyncio ORM (Object Relational Mapper) for several popular databases like sqlite, mysql, and postgresql.

Sanic Security includes default models for Tortoise, located in `orm/tortoise.py`. You can either use these, or supply your own as outlined in the [Custom](#orm-custom) section.

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

### μMongo
Sanic Security can use [μMongo ORM](https://umongo.readthedocs.io/en/latest/) for database operations. To use it, you must specify this via configuration value and it requires installation.

μMongo is a Python MongoDB ODM. It inception comes from two needs: the lack of async ODM and the difficulty to do document (un)serialization with existing ODMs.

Sanic Security includes default models for uMongo, located in `orm/umongo.py`. You can either use these, or supply your own as outlined in the [Custom](#orm-custom) section.

### Custom ORM
Sanic Security can also use any ORM or object/model system you want for database operations. To use it, you must specify this via configuration value, and provide your custom object classes at init time.

At a minimum, you will need to provide the `user` and `role` objects, and depending on other functionality you wish to use, may be required to provide the additional as listed below.

Each will be expected to have certain methods, that accept and return detail as defined below. A sample custom ORM using pure Python can be found in `tests/custom_orm.py`.

***
* #### **Account**
    * Required for `custom` provider usage.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |username|string|
    |password|string|
    |email|string|
    |phone|string|
    |disabled|bool|
    |verified|bool|
    |roles|list|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new user into the `Account` storage. Should perform all input validations.|
    |Args|`dict` containing the new user information: `username`, `email`, `password` (will be provided as a hash), `phone`, `disabled`, `verified`, `roles`|
    |Returns|New `Account` Object. Must contain at least a `pk` property for a unique identifier|
    
    |`json()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to convert an existing `Account` object into a JSON serializable `dict`|
    |Args|`self`|
    |Returns|`dict` representing the linked `Account`|
    
    |`validate()`|Details|
    |------------|-------|
    |desc|Checks the status of an `Account` object|
    |Args|`self`|
    |Returns|None|
    
    |`lookup()`|Details|
    |----------|-------|
    |Desc|(**async**) Abstraction method to find an existing user by provided identifier|
    |Args|(one of): `username`, `email`, `phone`, `id`|
    |Returns|Found `Account` Object. Must contain at least a `pk` property for a unique identifier|
    
    |`get_roles()`|Details|
    |-------------|-------|
    |Desc|(**async**) Abstraction method to provide the roles of an account for use in authorization lookups|
    |Args|Probably valid `id` or `Account` object|
    |Returns|`list` of roles for the identified user, or an empty `list`|
    
    |`add_roles()`|Details|
    |-------------|-------|
    |Desc|(**async**) Abstraction method to add a new `role` to an existing user
    |Args|*`id` or `Account` object to modify <br />*`role` object to add to the existing user|
    |Returns|Updated `Account` Object. Must contain at least a `pk` property for a unique identifier|
    
*** *
 * #### **Role**
    * Required for `custom` provider usage.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |name|string|
    |description|string|
    |permissions|string|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new role into the `Role` storage. Should perform all input validations.|
    |Args|`name`: Short name of the `Role`<br />`description`: Readable description of the `Role` <br /> `permissions`: CSV list of [rights](#authorization)|
    |Returns|New `Role` Object. Must contain at least a `pk` property for a unique identifier|
    
    |`lookup()`|Details|
    |----------|-------|
    |Desc|(**async**) Abstration method to find an existing role in the `Role` storage.|
    |Args|`name`: Short name of the `Role`|
    |Returns|Identified `Role` Object. Must contain at least a `pk` property for a unique identifier|

***
* #### **AuthenticationSession**
    * Required for `custom` provider usage.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |bearer|string|
    |ip|string|
    |expiration_date|`datetime` of ticket expiration|
    |refresh_expiration_date|`datetime` of refresh ticket expiration|
    |active|bool|
    |ctx|`SimpleNamespace()` (can be used to store additional encoded session data)|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new role into the `Session` storage.|
    |Args|tbd|
    |Returns|New `AuthenticationSession` Object. Must contain at least a `pk` property for a unique identifier|

    |`validate()`|Details|
    |-------|-------|
    |Desc|Abstration method to verify if the ticket is still good (not expired or deactivated)|
    |Args|`self`|
    |Raises|Exception for invalid reason|

    |`json()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to convert an existing `AuthenticationSession` object into a JSON serializable `dict`|
    |Args|`self`|
    |Returns|`dict` representing the linked `AuthenticationSession`|
    
***
* #### **VerificationSession**
    * Required for `custom` provider usage, where Client Verification is expected to be used.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |bearer||
    |ip|string|
    |expiration_date|`datetime` of ticket expiration|
    |ctx|`SimpleNamespace()` (can be used to store additional encoded session data)|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new role into the `Session` storage.|
    |Args|tbd|
    |Returns|New `VerificationSession` Object. Must contain at least a `pk` property for a unique identifier|

    |`validate()`|Details|
    |-------|-------|
    |Desc|Abstration method to verify if the ticket is still good (not expired or deactivated)|
    |Args|`self`|
    |Raises|Exception for invalid reason|

    |`json()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to convert an existing `VerificationSession` object into a JSON serializable `dict`|
    |Args|`self`|
    |Returns|`dict` representing the linked `VerificationSession`|

    |`check_code()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to check if code passed is equivalent to the session code.|
    |Args|`self`: `VerificationSession` object<br />request: Sanic `Request`<br />code: code to be cross checked|
    |Raises|Exception on invalid code verification attempt|
    
***
* #### **TwoStepValidationSession**
    * Required for `custom` provider usage, where Two Step Verification is expected to be used.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |bearer||
    |ip|string|
    |expiration_date|`datetime` of ticket expiration|
    |ctx|`SimpleNamespace()` (can be used to store additional encoded session data)|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new role into the `Session` storage.|
    |Args|tbd|
    |bearer||
    |Returns|New `TwoStepValidationSession` Object. Must contain at least a `pk` property for a unique identifier|

    |`validate()`|Details|
    |-------|-------|
    |Desc|Abstration method to verify if the ticket is still good (not expired or deactivated)|
    |Args|`self`|
    |Raises|Exception for invalid reason|

    |`json()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to convert an existing `TwoStepValidationSession` object into a JSON serializable `dict`|
    |Args|`self`|
    |Returns|`dict` representing the linked `TwoStepValidationSession`|
    
***
* #### **CaptchaValidationSession**
    * Required for `custom` provider usage, where Captcha Verification is expected to be used.

    At a minimum, the object must contain the following properties:

    |Field|Type|
    |-----|----|
    |id|string|
    |ip|string|
    |expiration_date|`datetime` of ticket expiration|
    |ctx|`SimpleNamespace()` (can be used to store additional encoded session data)|

    Additionally, the object must contain the following methods:

    |`new()`|Details|
    |-------|-------|
    |Desc|(**async**) Abstration method to insert a new role into the `Session` storage.|
    |Args|tbd|
    |Returns|New `CaptchaValidationSession` Object. Must contain at least a `pk` property for a unique identifier|

    |`validate()`|Details|
    |-------|-------|
    |Desc|Abstration method to verify if the ticket is still good (not expired or deactivated)|
    |Args|`self`|
    |Raises|Exception for invalid reason|

    |`json()`|Details|
    |--------|-------|
    |Desc|(**async**) Abstraction method to convert an existing `CaptchaValidationSession` object into a JSON serializable `dict`|
    |Args|`self`|
    |Returns|`dict` representing the linked `CaptchaValidationSession`|
    
    
###

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Setup poetry: `poetry install`
3. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
4. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
5. Verify unit tests are passing: `poetry run pytest -ra`
6. Push to the Branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request


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
