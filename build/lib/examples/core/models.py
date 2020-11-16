from sanic.response import json
from tortoise import fields

from amyrose.core.models import BaseModel


def base_response(message, content):
    return json({
        'Message': message,
        'Content': content
    })


class ForumEntry(BaseModel):
    parent_name = fields.CharField(max_length=45)
    title = fields.CharField(max_length=45)
    content = fields.CharField(max_length=255)
