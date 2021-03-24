from sanic.response import json as sanic_json


def json(message, content, status_code=200):
    payload = {
        'message': message,
        'status_code': status_code,
        'content': content
    }
    return sanic_json(payload, status=status_code)
