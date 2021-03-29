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



<!-- PROJECT LOGO -->
<br />
<p align="center">

  <h3 align="center">Async Auth</h3>

  <p align="center">
    A powerful, simple, and async authentication and authorization library for Sanic.
    <br />
    <a href="http://authdoc.sunsetdeveloper.com/">Documentation</a>
    ·
    <a href="https://github.com/sunset-developer/Amy-Rose/issues">Report Bug</a>
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
    * [Verification](#verification)
    * [Authorization](#authorization)
    * [Error Handling](#error-handling)
    * [Middleware](#Middleware)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)



<!-- ABOUT THE PROJECT -->
## About The Project

Async Auth is an authentication and authorization library made easy. Specifically designed for use with [Sanic](https://github.com/huge-success/sanic).
This library comes packed with features such as:

* SMS and email verification
* Easy login and registering
* JWT
* Easy database integration
* Wildcard permissions
* Role permissions
* Captcha
* Password recovery
* Completely async

This repository has been starred by Sanic's core maintainer:

![alt text](https://github.com/sunset-developer/asyncauth/blob/master/images/ahopkins.png)

Documentation is currently auto generated. This is a placeholder until I write out better documentation.

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
pip3 install asyncauth
```


## Usage

Once Async Auth is all setup and good to go, implementing is easy as pie.

### Initial Setup

First you have to create a configuration file called auth.ini. Below is an example of it's contents: 

```
[ROSE]
secret=05jF8cSMAdjlXcXeS2ZJUHg7Tbyu
captcha_font=source-sans-pro.light.ttf

[TORTOISE]
username=admin
password=8KjLQtVKTCtItAi
endpoint=asyncauth.cbwyreqgyzf6b.us-west-1.rds.amazonaws.com
schema=asyncauth
models=asyncauth.core.models
generate=true

[TWILIO]
from=+12058469963
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

Once you've configured Async Auth, you can initialize Sanic with the example below:

```python
if __name__ == '__main__':
    initialize_auth(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
``` 

Most request bodies should be sent as `form-data`. For my below examples, I use my own custom json method:

```python
def json(message, content, status_code=200):
    payload = {
        'message': message,
        'status_code': status_code,
        'content': content
    }
    return sanic_json(payload, status=status_code)
```

## Authentication

* Registration (With all verification requirements)

Phone can be null or empty.

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | +19811354186
**password** | testpass
**captcha** | Aj8HgD

```python
@app.post('api/register')
@requires_captcha()
async def on_register(request, captcha_session):
    verification_session = await register(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    response = json('Registration successful', verification_session.account.json())
    verification_session.encode(response)
    return response
```

* Registration (Without verification requirements)

Phone can be null or empty.

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | +19811354186
**password** | testpass

```python
@app.post('api/register')
async def on_register(request):
    account = await register(request, verified=True)
    return json('Registration Successful!', account.json())
```

* Login

Key | Value |
--- | --- |
**email** | test@test.com
**password** | testpass

```python
@app.post('api/login')
async def on_login(request):
    authentication_session = await login(request)
    response = json('Login successful!', authentication_session.account.json())
    authentication_session.encode(response)
    return response
```

* Logout

```python
@app.post('api/logout')
async def on_logout(request):
    authentication_session = await logout(request)
    response = json('Logout successful', authentication_session.account.json())
    return response
```

* Account Recovery Request

This request is sent with an url argument instead of `form-data`.

Key | Value |
--- | --- |
**email** | test@test.com

```python
@app.get('api/recovery/request')
async def on_recovery_request(request):
    verification_session = await request_account_recovery(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    response = json('Recovery request successful', verification_session.json())
    verification_session.encode(response)
    return response
```


* Account Recovery

Key | Value |
--- | --- |
**code** | G8ha9nVa
**password** | newpass

```python
@app.post('api/recovery')
@requires_verification()
async def on_recovery(request, verification_session):
    await account_recovery(request, verification_session)
    return json('Account recovered successfully', verification_session.account.json())
```

* Requires Authentication

```python
@app.get('api/authentication')
@requires_authentication()
async def on_authentication(request, authentication_session):
    return json('Hello ' + authentication_session.account.username + '! You are now authenticated.', 
                authentication_session.account.json())
```


## Verification

You must download a .ttf font for captcha challenges and define the file's path in auth.ini.

* Request Captcha

```python
@app.get('api/captcha')
async def on_request_captcha(request):
    captcha_session = await request_captcha(request)
    response = json('Captcha request successful!', captcha_session.json())
    captcha_session.encode(response)
    return response
```

* Captcha Image

```python
@app.get('api/captcha/img')
async def on_captcha_img(request):
    img_path = await CaptchaSession().captcha_img(request)
    return await file(img_path)
```

* Request Verification (Creates and encodes a new verification code, useful for when a verification session may be invalidated)

```python
@app.get('api/verification/request')
async def on_request_verification(request):
    verification_session = await request_verification(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    response = json('Verification request successful', verification_session.json())
    verification_session.encode(response)
    return response
```

* Resend Verification (Does not create new verification code, simply resends the code)

```python
@app.get('api/verification/resend')
async def on_resend_verification(request):
    verification_session = await VerificationSession().decode(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    return json('Verification code resend successful', verification_session.json())
```

* Verify Account

Key | Value |
--- | --- |
**code** | G8ha9nVae

```python
@app.post('api/register/verify')
@requires_verification()
async def on_verify(request, verification_session):
    await verify_account(verification_session)
    return json('Verification successful!', verification_session.json())
```

* Requires Verification

Key | Value |
--- | --- |
**code** | G8ha9nVa


```python
@app.post('api/verification')
@requires_verification()
async def on_verification(request, verification_session):
    return json('Hello ' + verification_session.account.username + '! You have verified yourself!', 
                authentication_session.account.json())
```

## Authorization

Async Auth comes with two protocols for authorization: role based and wildcard based permissions.

* Role-based access control (RBAC) is a policy-neutral access-control mechanism defined around roles and privileges. The components of RBAC such as role-permissions, user-role and role-role relationships make it simple to perform user assignments. 

* Wildcard permissions support the concept of multiple levels or parts. For example, you could restructure the previous simple example by granting a user the permission
`printer:query`. The colon in this example is a special character used to delimit the next part in the permission string. In this example, the first part is the domain that is being operated on (printer), and the second part is the action (query) being performed. 

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
@app.post('api/account/update')
@require_permissions('admin:update', 'employee:add')
async def on_require_perms(request, authentication_session):
    return text('Admin successfully updated account!')
```

* Require Roles

```python
@app.get('api/dashboard/admin')
@require_roles('Admin', 'Moderator')
async def on_require_roles(request, authentication_session):
    """
    Tests client role authorization access.
    """
    return text('Admin gained access!')
```

## Error Handling

```python
@app.exception(AuthError)
async def on_error(request, exception):
    return json('An error has occurred!', {
        'error': type(exception).__name__,
        'summary': str(exception)
    }, status_code=exception.status_code)
```

## Middleware

```python
@app.middleware('response')
async def response_middleware(request, response):
    xss_prevention(request, response)


@app.middleware('request')
async def request_middleware(request):
    return https_redirect(request)
```

<!-- ROADMAP -->
## Roadmap

Keep up with Async Auth's [Trello](https://trello.com/b/aRKzFlRL/amy-rose) board for a list of proposed features, known issues, and in progress development.


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



<!-- CONTACT -->
## Contact

Aidan Stewart - aidanstewart@sunsetdeveloper.com

Project Link: [https://github.com/sunset-developer/Amy-Rose](https://github.com/sunset-developer/Amy-Rose)


<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements

* [Be the first! Submit a pull request.](https://github.com/sunset-developer/PyBus3/pulls)


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/sunset-developer/Amy-Rose.svg?style=flat-square
[contributors-url]: https://github.com/sunset-developer/Amy-Rose/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/sunset-developer/Amy-Rose.svg?style=flat-square
[forks-url]: https://github.com/sunset-developer/Amy-Rose/network/members
[stars-shield]: https://img.shields.io/github/stars/sunset-developer/Amy-Rose.svg?style=flat-square
[stars-url]: https://github.com/sunset-developer/Amy-Rose/stargazers
[issues-shield]: https://img.shields.io/github/issues/sunset-developer/Amy-Rose.svg?style=flat-square
[issues-url]: https://github.com/sunset-developer/Amy-Rose/issues
[license-shield]: https://img.shields.io/github/license/sunset-developer/Amy-Rose.svg?style=flat-square
[license-url]: https://github.com/sunset-developer/Amy-Rose/blob/master/LICENSE
