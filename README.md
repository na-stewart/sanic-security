<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Conda](https://anaconda.org/conda-forge/sanic-security/badges/installer/conda.svg)](https://anaconda.org/conda-forge/sanic-security)
[![Downloads](https://pepy.tech/badge/sanic-security)](https://pepy.tech/project/sanic-security)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">Sanic Security</h3>
  <p align="center">
   An effective, simple, and async security library for Sanic.
  </p>
</p>


<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
    * [Initial Setup](#initial-setup)
    * [Authentication](#authentication)
    * [Captcha](#captcha)
    * [Two Step Verification](#two-step-verification)
    * [Authorization](#authorization)
    * [Testing](#testing)
* [Tortoise](#tortoise)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#Versioning)


<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication, authorization, and verification library designed for use with [Sanic](https://github.com/huge-success/sanic).
This library contains a variety of features including:

* Login, registration, and authentication
* Two-step verification
* Two-factor authentication
* Captcha
* Wildcard and role based authorization

This repository has been starred by Sanic's core maintainer:

[![aphopkins](https://github.com/sunset-developer/sanic-security/blob/main/images/ahopkins.png)](https://github.com/ahopkins)

Please visit [security.sunsetdeveloper.com](https://security.sunsetdeveloper.com) for more information and documentation.

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install pip.

### Prerequisites

* pip
```sh
sudo apt-get install python3-pip
```


### Installation

* Install the Sanic Security pip package.
```sh
pip3 install sanic-security
````

## Usage

Sanic Security setup and implementation is easy.

### Initial Setup

First you have to create a configuration file called security.ini in the working directory. Below is an example of its contents:

```ini
[SECURITY]
secret=05jF8cSMAdjlXcXeS2ZJUHg7Tbyu
captcha_font=captcha.ttf
cache_path = ./resources/security-cache
session_samesite = strict

[TORTOISE]
username=example
password=8UVbijLUGYfUtItAi
endpoint=example.cweAenuBY6b.us-north-1.rds.amazonaws.com
schema=exampleschema
models=sanic_security.models, example.models
engine=mysql
generate=true
```

Once you've configured Sanic Security, you can initialize Sanic with the example below:

```python
initialize_security_orm(app)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
```

All request bodies must be sent as `form-data`. The tables in the below examples represent example request form data.

## Authentication

* Registration

Phone can be null or empty.

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | 19811354186
**password** | testpass
**captcha** | Aj8HgD

```python
@app.post("api/auth/register")
@requires_captcha()
async def on_register(request, captcha_session):
    account = await register(request)
    two_step_session = await request_two_step_verification(request, account)
    await email_code(two_step_session.code) #Custom method for emailing verification code.
    response = json("Registration successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response
```

* Verify Account

Key | Value |
--- | --- |
**code** | G8ha9nVae

```python
@app.post("api/auth/verify")
async def on_verify(request):
    two_step_session = await verify_account(request)
    return json("You have verified your account and may login!", two_step_session.account.json())
```

* Login

Key | Value |
--- | --- |
**email** | test@test.com
**password** | testpass

```python
@app.post("api/auth/login")
async def on_login(request):
    authentication_session = await login(request)
    response = json("Login successful!", authentication_session.account.json())
    authentication_session.encode(response)
    return response
```

* Login (With two-factor authentication)

Key | Value |
--- | --- |
**email** | test@test.com
**password** | testpass


```python
@app.post("api/auth/login")
async def on_two_factor_login(request):
    authentication_session = await login(request, two_factor=True)
    two_step_session = await request_two_step_verification(request, authentication_session.account)
    await email_code(two_step_session.code) #Custom method for emailing verification code.
    response = json("Login successful! A second factor is now required to be authenticated.", authentication_session.account.json())
    authentication_session.encode(response)
    two_step_session.encode(response)
    return response
```

* Second Factor

Key | Value |
--- | --- |
**code** | G8ha9nVae

```python
@app.post("api/auth/login/second-factor")
@requires_two_step_verification()
async def on_login_second_factor(request, two_step_verification):
  authentication_session = await on_second_factor(request)
  response = json("Second factor attempt successful! You may now be authenticated!",
                  authentication_session.account.json())
  return response
```

* Logout

```python
@app.post("api/auth/logout")
@requires_authentication()
async def on_logout(request, authentication_session):
    await logout(authentication_session)
    response = json("Logout successful!", authentication_session.account.json())
    return response
```

* Requires Authentication

```python
@app.post("api/auth/authenticate")
@requires_authentication()
async def on_authenticated(request, authentication_session):
    return json(f"Hello {authentication_session.account.username}! You have been authenticated.", 
                authentication_session.account.json())
```

## Captcha

You must download a .ttf font for captcha challenges and define the file's path in security.ini.

[1001 Free Fonts](https://www.1001fonts.com/)

[Recommended Font](https://www.1001fonts.com/source-sans-pro-font.html)

Captcha challenge example:

[![Captcha image.](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)

* Request Captcha

```python
@app.post("api/captcha/request")
async def on_request_captcha(request):
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.json())
    captcha_session.encode(response)
    return response
```

* Captcha Image

```python
@app.get("api/captcha/img")
async def on_captcha_img(request):
    captcha_session = await CaptchaSession.decode(request)
    return await captcha_session.get_image()
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
**email** | test@test.com
**captcha** | Aj8HgD

```python
@app.post("api/verification/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    two_step_session = await request_two_step_verification(request)
    await email_code(two_step_session.code) #Custom method for emailing verification code.
    response = json("Verification request successful!", two_step_session.account.json())
    two_step_session.encode(response)
    return response
```

* Resend Two-step Verification Code

```python
@app.post("api/verification/resend")
async def on_resend_verification(request):
    two_step_session = await TwoStepSession.decode(request)
    await email_code(two_step_session.code) #Custom method for emailing verification code.
    return json("Verification code resend successful!", two_step_session.account.json())
```

* Requires Two-step Verification

Key | Value |
--- | --- |
**code** | G8ha9nVa

```python
@app.post("api/verification")
@requires_two_step_verification()
async def on_verification(request, two_step_session):
    response = json("Two-step verification attempt successful!", two_step_session.account.json())
    return response
```

## Authorization

Sanic Security comes with two protocols for authorization: role based and wildcard based permissions.

Role-based access control (RBAC) is a policy-neutral access-control mechanism defined around roles and privileges. 

Wildcard permissions support the concept of multiple levels or parts. For example, you could grant a user the permission
`printer:query`, `printer:query,delete`, `printer:*`.

* Require Permissions

```python
@app.post("api/auth/perms")
@require_permissions("admin:update", "employee:add")
async def on_require_perms(request, authentication_session):
    return text("Account permitted.")
```

* Require Roles

```python
@app.post("api/auth/roles")
@require_roles("Admin", "Moderator")
async def on_require_roles(request, authentication_session):
    return text("Account permitted.")
```

## Testing

Make sure the test Sanic instance (`test/server.py`) is running on your machine.

Run the unit test client (`test/client.py`) and wait for results.

## Tortoise

Sanic Security uses [Tortoise ORM](https://tortoise-orm.readthedocs.io/en/latest/index.html) for database operations.

Tortoise ORM is an easy-to-use asyncio ORM (Object Relational Mapper).

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
tournament = Tournament(name='New Tournament')
await tournament.save()

# Or by .create()
await Tournament.create(name='Another Tournament')

# Now search for a record
tour = await Tournament.filter(name__contains='Another').first()
print(tour.name)
```

<!-- ROADMAP -->
## Roadmap

Keep up with Sanic Security's [Trello](https://trello.com/b/aRKzFlRL/amy-rose) board for a list of proposed features, known issues, and in progress development.

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

Distributed under the GNU General Public License v3.0. See `LICENSE` for more information.

<!-- Versioning -->
## Versioning

**0.0.0.0**

Major.Minor.Revision.Patch

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
