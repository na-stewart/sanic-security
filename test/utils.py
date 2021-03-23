from sanic.exceptions import ServerError


def check_for_empty(form, *args):
    for key, value in form.items():
        if value is not None:
            if not isinstance(value[0], bool) and not value[0] and key not in args:
                raise ServerError(key + " is empty!", 400)
