from configparser import ConfigParser

config_path = './rose.ini'
config = ConfigParser()


def read_config():
    config.read(config_path)


read_config()
