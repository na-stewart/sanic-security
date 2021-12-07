class Config(dict):


    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError()

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError()


config = Config(
    {
        "secret": "This is a big secret. Shhhhh",
        "cache": "./resources/security-cache",
        "session_samesite": "strict",
        "session_secure": False,
        "captcha_session_expiration": 60,
        "captcha_font": "captcha.ttf",
        "two_step_session_expiration": 300,
        "authentication_session_expiration": 2592000,
        "two_factor_overrride": False
    }
)
