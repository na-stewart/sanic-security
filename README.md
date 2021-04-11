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

  <h3 align="center">Sanic Security</h3>

  <p align="center">
   A powerful, simple, and async security library for Sanic.
    <br />
    <a href="http://security.sunsetdeveloper.com/">Documentation</a>
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
    * [Recovery](#recovery)
    * [Captcha](#captcha)
    * [Verification](#verification)
    * [Authorization](#authorization)
    * [IP2Proxy](#ip2proxy)
    * [Error Handling](#error-handling)
    * [Middleware](#Middleware)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)



<!-- ABOUT THE PROJECT -->
## About The Project

Sanic Security is an authentication and authorization library made easy, designed for use with [Sanic](https://github.com/huge-success/sanic).
This library is intended to be easy, convenient, and contains a variety of easy to implement features:


* Easy login and registering
* Captcha
* SMS and email verification
* JWT
* Password recovery
* Wildcard permissions
* Role permissions
* IP2Proxy support
* Easy database integration
* Completely async

This repository has been starred by Sanic's core maintainer:

![alt text](https://github.com/sunset-developer/asyncauth/blob/master/images/ahopkins.png)

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
```


## Usage

Once Sanic Security is configured and good to go, implementing is easy as pie.

### Initial Setup

First you have to create a configuration file called auth.ini in the project directory. Make sure Python's 
working directory is the project directory. Below is an example of its contents: 

WARNING: You must set a custom secret, or you will compromise your encoded sessions.

```
[AUTH]
name=ExampleProject
secret=05jF8cSMAdjlXcXeS2ZJUHg7Tbyu
captcha_font=source-sans-pro.light.ttf

[TORTOISE]
username=admin
password=8UVbijLUGYfUtItAi
endpoint=website.cweAenuBY6b.us-north-1.rds.amazonaws.com
schema=webschema
models=sanic_security.core.models
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

[IP2PROXY]
key=iohuyg87UGYOFijoTYG8HOuhuZJsdXwjqbhuyghuiBUYG8yvo6J
code=PX1LITEBIN
bin=IP2PROXY-LITE-PX1.BIN
```

You may remove each section in the configuration you aren't using.

Once you've configured Sanic Security, you can initialize Sanic with the example below:

```python
if __name__ == '__main__':
    initialize_security(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
``` 

WARNING: When you use a reverse proxy server (e.g. nginx), the value of ip address may contain the IP of a proxy, 
typically 127.0.0.1. Almost always, this is not what you will want. [Click here for more information!](https://sanicframework.org/en/guide/advanced/proxy-headers.html)

All request bodies should be sent as `form-data`. For my below examples, I use my own custom json method:

```python
from sanic.response import json as sanic_json
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

Phone can be null or empty. A captcha request must be made.

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | 19811354186
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
**phone** | 19811354186
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

* Requires Authentication

```python
@app.get('api/client')
@requires_authentication()
async def on_authenticated(request, authentication_session):
    return json('Hello ' + authentication_session.account.username + '! You are now authenticated.', 
                authentication_session.account.json())
```

## Recovery

* Account Recovery Request

This request is sent with an url argument instead of `form-data`.

Key | Value |
--- | --- |
**email** | test@test.com

```python
@app.get('api/recovery/request')
@requires_captcha()
async def on_recovery_request(request, captcha_session):
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
async def on_recovery(request):
    await account_recovery(request, verification_session)
    return json('Account recovered successfully', verification_session.account.json())
```


## Captcha

You must download a .ttf font for captcha challenges and define the file's path in auth.ini.

[1001 Free Fonts](https://www.1001fonts.com/)

[Recommended Font](https://www.1001fonts.com/source-sans-pro-font.html)

Captcha challenge example:

![alt text](https://github.com/sunset-developer/asyncauth/blob/master/images/captcha.png)

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

* Require Captcha

Key | Value |
--- | --- |
**captcha** | Aj8HgD

```python
@app.post('api/captcha/attempt')
@requires_captcha()
async def on_captcha_attempt(request, captcha_session):
    response = json('Your captcha attempt was correct!', captcha_session.json())
    return response
```

## Verification

* Request Verification (Creates and encodes a new verification code, useful for when a verification session may be 
  invalid or expired.)

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

* Resend Verification (Does not create new verification code, only resends current session code.)

```python
@app.get('api/verification/resend')
async def on_resend_verification(request):
    verification_session = await VerificationSession().decode(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    return json('Verification code resend successful', verification_session.json())
```

* Requires Verification

Key | Value |
--- | --- |
**code** | G8ha9nVa

```python
@app.post('api/client')
@requires_verification()
async def on_verified(request, verification_session):
    return json('Hello ' + verification_session.account.username + '! You have verified yourself and may continue. ', 
                authentication_session.account.json())
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
    return text('Admin gained access!')
```

## IP2Proxy

[IP2Location](https://www.ip2location.com/)

[IP2Location LITE](https://lite.ip2location.com/)

IP2Proxy Proxy Detection Database contains IP addresses which are used as VPN anonymizer, open proxies, web proxies
and Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential proxies (RES).

Anonymous proxy servers are intermediate servers meant to hide the real identity or IP address of the requestor. 
Studies found that a large number of anonymous proxy users are generally responsible for online credit card fraud, 
forums and blogs spamming.

IP2Proxy database is based on a proprietary detection algorithm in parallel with evaluation of anonymous open proxy 
servers which are actively in use. Then it generates an up-to-date list of anonymous proxy IP address in the download 
area every 24 hours.

DISCLAIMER: There is no real good “out-of-the-box” solution against fake IP addresses, aka “IP Address Spoofing”. Do not
rely on IP2Proxy to provide 100% protection against malicious actors utilizing proxies/vpns.

* Detect Proxy
```python
@app.get('api/recovery/request')
@detect_proxy()
@requires_captcha()
async def on_recovery_request(request, captcha_session):
    verification_session = await request_account_recovery(request)
    await verification_session.text_code() # Text verification code.
    await verification_session.email_code() # Or email verification code.
    response = json('Recovery request successful', verification_session.json())
    verification_session.encode(response)
    return response
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
async def xxs_middleware(request, response):
    xss_prevention_middleware(request, response)


@app.middleware('request')
async def https_middleware(request):
    return https_redirect_middleware(request)


@app.middleware('request')
async def ip2proxy_middleware(request):
    await proxy_detection_middleware(request)
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
