import os


def path_exists(path):
    """
    Checks if path exists, and creates it if it doesn't.

    :param path: Path being checked.

    :return: exists
    """
    exists = os.path.exists(path)
    if not exists:
        os.makedirs(path)
    return exists
