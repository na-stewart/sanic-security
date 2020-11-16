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
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">

  <h3 align="center">Amy Rose</h3>

  <p align="center">
    A powerful yet simple async authentication and authorization library for Sanic.
    <br />
    <a href="https://github.com/sunset-developer/Amy-Rose/tree/master/examples">View Demo</a>
    ·
    <a href="https://github.com/sunset-developer/Amy-Rose/issues">Report Bug</a>
    ·
    <a href="https://github.com/sunset-developer/Amy-Rose/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
    * [Initial Setup](#initial-setup)
    * [Authentication](#authentication)
    * [Authorization](#authorization)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)



<!-- ABOUT THE PROJECT -->
## About The Project

Amy Rose is an authentication and authorization library made easy. Specifically designed for use with [Sanic](https://github.com/huge-success/sanic).
Amy Rose comes packed with features not found in most open source security libraries such as

* SMS verification
* JWT
* Out of the box database integration
* Wildcard permissions
* Role permissions

Amy Rose contains all of your basic security needs.

### Built With
* [Tortoise](https://tortoise.github.io/)
* [Sanic](https://github.com/huge-success/sanic)
* [Twilio](https://www.twilio.com/)



<!-- GETTING STARTED -->
## Getting Started

In order to get started, please install pip.

### Prerequisites

* pip
```sh
sudo apt-get install python3-pip
```


### Installation

* Clone the repo
```sh
git clone https://github.com/sunset-developer/Amy-Rose
```
* Install pip packages
```sh
pip3 install amyrose
```


## Usage

Once Amy Rose is all setup and good to go, implementing is easy as pie.

### Initial Setup

First you have to create a configuration file called rose.ini. Below is an example of it's contents: 

```
[ROSE]
secret=05jF8cSMAdjlXcXeS2ZJ

[TORTOISE]
username=admin
password=8KjLQtVKTCtItAi
endpoint=amyrose.cbwyreqgyzf6b.us-west-1.rds.amazonaws.com
schema=amyrose
models=['amyrose.core.models']
generate=true

[TWILIO]
from=+12058469963
token=1bcioi878ygO8fi766Fb34750e82a5ab
sid=AC6156Jg67OOYe75c26dgtoTICifIe51cbf
```

If you're initializing Tortoise yourself you do not have to configure it here.

If you're not using Twilio as your verification method, you do not have to configure it here. 

Once you've configured Amy Rose, you can initialize Sanic with the example below:

```
if __name__ == '__main__':
    app.add_task(tortoise_init())
    app.run(host='0.0.0.0', port=8000, debug=True)
``` 

All request bodies should be sent as `form-data`

## Authentication

* Registration

Key | Value |
--- | --- |
**username** | test 
**email** | test@test.com 
**phone** | +19876854892
**password** | testpass


```python
@app.post('/register')
async def on_register(request):
    account, verification_session = await register(request)
    await text_verification_code(account, verification_session)
    response = text('Registration successful')
    response.cookies[verification_session.get_cookie_name()] = verification_session.to_cookie()
    return response
```

* Verification

Key | Value |
--- | --- |
**code** | GUmrRLD


```python
@app.post('/verify')
async def on_verify(request):
    account, verification_session = await verify_account(request)
    return text('Verification successful')
```


* Login

Key | Value |
--- | --- |
**email** | test@test.com
**password** | testpass


```python
@app.post('/login')
async def on_login(request):
    account, authentication_session = await login(request)
    response = text('Login successful')
    response.cookies[authentication_session.get_cookie_name()] = authentication_session.to_cookie()
    return response
```

* Requires Authentication

```python
@app.get("/get")
@requires_authentication()
async def get_user_info(request):
    return text('Sensitive user information')
```

## Authorization

Examples of wildcard permissions are:

```
admin:add,update,delete
admin:add
admin:*
employee:add,delete
employee:delete
employee:*
```

A library called [Apache Shiro](https://shiro.apache.org/permissions.html) explains this concept incredibly well. I 
absolutely recommend this library for Java developers.

* Requires Role

```python
@app.get('/update')
@requires_permission('admin:update')
async def on_test_perm(request):
    return text('Admin has manipulated very sensitive data') 
```

* Requires Permission

```python
@app.get('/get')
@requires_role('Admin')
async def on_test_role(request):
    return text('Admin has retrieved very sensitive data')
```

<!-- ROADMAP -->
## Roadmap

Keep up with Amy Rose's [Trello](https://trello.com/b/aRKzFlRL/amy-rose) board for a list of proposed features, known issues, and in progress development.


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
