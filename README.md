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
[![Downloads](https://pepy.tech/badge/sanic-security)](https://pepy.tech/project/sanic-security)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)


<!-- PROJECT LOGO -->
<br />
<p align="center">

  <h3 align="center">Sanic Security</h3>

  <p align="center">
   A powerful, simple, and async security library for Sanic.
    <br />
    <a href="http://security.sunsetdeveloper.com/">Documentation</a>
    ·
    <a href="https://github.com/sunset-developer/sanic-security/issues">Report Bug</a>
    ·
    <a href="https://github.com/sunset-developer/asyncauth/pulls">Request Feature</a>
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
    * [Error Handling](#error-handling)
    * [Blueprints](#blueprints)
    * [Testing](#testing)
* [Tortoise](#tortoise)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Versioning](#Versioning)




<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication and authorization library made easy, designed for use with [Sanic](https://github.com/huge-success/sanic).
This library is intended to be easy, convenient, and contains a variety of features:

* Easy login and registering
* Text and email verification
* Two-factor authentication
* Captcha
* JWT
* Wildcard permissions
* Role permissions
* Blueprints

This repository has been starred by Sanic's core maintainer:

![alt text](https://github.com/sunset-developer/sanic-security/blob/main/images/ahopkins.png)

<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install pip.

### Prerequisites

* pip
```sh
sudo apt-get install python3-pip
```


### Installation

* Install pip packages
```sh
pip3 install sanic-security
````

## Usage

Once Sanic Security is configured and good to go, implementing is easy.

### Initial Setup

First you have to create a configuration file called security.ini in the working directory. Below is an example of its contents:

```ini
[SECURITY]
secret=05jF8cSMAdjlXcXeS2ZJUHg7Tbyu
captcha_font=source-sans-pro.light.ttf

[BLUEPRINT]
register_route=api/auth/register
login_route=api/auth/login
verify_route=api/auth/verify
logout_route=api/auth/logout
captcha_request_route=api/capt/request
captcha_img_route=api/capt/img

[TORTOISE]
username=admin
password=8UVbijLUGYfUtItAi
endpoint=example.cweAenuBY6b.us-north-1.rds.amazonaws.com
schema=exampleschema
models=sanic_security.models, example.models
engine=mysql
generate=true

[TWILIO]
from=12058469963
token=1bcioi878ygO8fi766Fb34750e82a5ab
sid=AC6156Jg67OOYe75c26dgtoTICifIe51cbf

[SMTP]
host=smtp.gmail.com
port=465
from=test@gmail.com
username=test@gmail.com
password=wfrfouwiurhwlnj
tls=true
start_tls=false
```

You may remove each section in the configuration you aren't using. For example, if you're not utilizing Twillio you can
delete the `TWILLIO` section.

Once you've configured Sanic Security, you can initialize Sanic with the example below:

```python
initialize_security_orm(app)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
```

All request bodies must be sent as `form-data`. The tables in the below examples represent example request form data.

## Authentication

* Registration (With all verification requirements)

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
    two_step_session = await register(request)
    await two_step_session.text_code() # Text verification code.
    await two_step_session.email_code() # Or email verification code.
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

* Registration (Without verification requirements)

Phone can be null or empty.

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | 19811354186
**password** | testpass

```python
@app.post("api/auth/register")
async def on_register(request):
    account = await register(request, verified=True)
    return json("Registration Successful!", account.json())
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
    await two_step_session.text_code() # Text verification code.
    await two_step_session.email_code() # Or email verification code.
    response = json("Login successful! A second factor is now required to be authenticated.", authentication_session.account.json())
    authentication_session.encode(response)
    two_step_session.encode(response)
    return response
```

* Second Factor

```python
@app.post("api/auth/login/second-factor")
@requires_two_step_verification()
async def on_second_factor(request, two_step_verification):
  authentication_session = await validate_second_factor(request)
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
@app.get("api/auth/authenticate")
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

![alt text](https://github.com/sunset-developer/sanic-security/blob/main/images/captcha.png)

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
@app.post("api/captcha/attempt")
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    return json("Captcha attempt successful!", captcha_session.json())
```

## Two-Step Verification

* Request Two-step Verification (creates and encodes a two-step session)

Requesting verification should be conditional. For example, an account that is logging in is unverified and requires verification. The example below is not conditional.

Key | Value |
--- | --- |
**email** | test@test.com
**captcha** | Aj8HgD

```python
@app.post("api/verification/request")
@requires_captcha()
async def on_request_verification(request, captcha_session):
    two_step_session =  await request_two_step_verification(request)
    await two_step_session.text_code() # Text verification code.
    await two_step_session.email_code() # Or email verification code.
    response = json("Verification request successful!", two_step_session.json())
    two_step_session.encode(response)
    return response
```

* Resend Two-step Verification Code (Does not create new two-step session, only resends existing session code)

```python
@app.post("api/verification/resend")
async def on_resend_verification(request):
    two_step_session = await TwoStepSession.decode(request)
    await two_step_session.text_code() # Text verification code.
    await two_step_session.email_code() # Or email verification code.
    return json("Verification code resend successful!", two_step_session.json())
```

* Requires Two-Step Verification

Key | Value |
--- | --- |
**code** | G8ha9nVa

```python
@app.post("api/verification/attempt")
@requires_two_step_verification()
async def on_verified(request, two_step_session):
    response = json("Two-step verification attempt successful!", two_step_session.json())
    return response
```

## Authorization

Sanic Security comes with two protocols for authorization: role based and wildcard based permissions.

Role-based access control (RBAC) is a policy-neutral access-control mechanism defined around roles and privileges. The components of RBAC such as role-permissions, user-role and role-role relationships make it simple to perform user assignments. 

Wildcard permissions support the concept of multiple levels or parts. For example, you could grant a user the permission
`printer:query`. The colon in this example is a special character used to delimit the next part in the permission string. In this example, the first part is the domain that is being operated on (printer), and the second part is the action (query) being performed. 
This concept was inspired by [Apache Shiro's](https://shiro.apache.org/static/1.7.1/apidocs/org/apache/shiro/authz/permission/WildcardPermission.html) implementation of wildcard based permissions.

Examples of wildcard permissions are:

  ```
  admin:add,update,delete
  admin:add
  admin:*
  employee:add,delete
  employee:delete
  employee:*
  ```

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
    return text("Account permitted")
```

## Error Handling

```python
@app.exception(SecurityError)
async def on_error(request, exception):
    return exception.response
```

## Blueprints

Sanic Security blueprints contain endpoints that allow you to employ fundamental authentication and verification into your application with a
single line of code. 

* Implementation

```python
app.blueprint(security)
```
* Endpoints

Method | Endpoint | Info |
--- | --- | --- |
POST | api/auth/register | A captcha is required. Register an account with an email, username, and password. Once the account is created successfully, a two-step session is requested and the code is emailed.
POST | api/auth/login | Login with an email and password. A two-step session is requested when the account is not verified and the code is emailed.
POST | api/auth/verify | Verify account with a two-step session code found in email.
POST | api/auth/logout | Logout of logged in account.
POST | api/capt/request | Requests new captcha session.
GET | api/capt/img | Retrieves captcha image from existing captcha session.

## Testing

Make sure the test Sanic instance (`test/server.py`) is running on your machine as both postman, and the unit tests operate as a test client.

Then run the unit tests (`test/tests.py`) or test with postman via clicking the button below.

[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/d3667ed325439e0ffd6e?action=collection%2Fimport)


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
