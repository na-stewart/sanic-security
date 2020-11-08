import os
from configparser import ConfigParser

cache_path = '../rosecache'
config_path = cache_path + '/' + 'config.ini'
config_parser = ConfigParser()


def write_to_config():
    with open('config.ini', 'w+') as configfile:
        config_parser.write(configfile)


def clear_cache():
    for root, dirs, files in os.walk(cache_path):
        for file in files:
            os.remove(os.path.join(root, file))


def read_config():
    config_parser.read(config_path)


if not os.path.exists(cache_path):
    os.makedirs(cache_path)
