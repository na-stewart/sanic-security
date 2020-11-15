from sanic.response import json
from tortoise import fields

from amyrose.core.models import BaseModel


class ForumEntry(BaseModel):
    parent_name = fields.CharField(max_length=45)
    content = fields.CharField(max_length=255)


class BaseResponse(json):
    def __init__(self, message, content):
        super().__init__({
            'message': message,
            'content': content,
        })
