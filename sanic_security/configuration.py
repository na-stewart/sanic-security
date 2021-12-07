class Config(object):
    def __init__(self, initial_data):
        for key in initial_data:
            setattr(self, key, initial_data[key])


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
    }
)
