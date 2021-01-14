from configparser import ConfigParser

config_path = './rose.ini'
config_parser = ConfigParser()


def read_config():
    config_parser.read(config_path)



read_config()
