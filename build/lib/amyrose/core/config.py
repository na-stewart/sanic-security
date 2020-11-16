import os
from configparser import ConfigParser

config_path = '../rose.ini'
config_parser = ConfigParser()


def write_to_config():
    with open(config_path, 'w+') as configfile:
        config_parser.write(configfile)


def read_config():
    config_parser.read(config_path)


read_config()



