import configparser
import collections
import sys

class CustomConfigParser:
    def __init__(self):
        self.settings = {}

    def load_conf(self,CONFIG_PATH):
        """Provided a config file path and a collections of type dict,
        will return that collections with all the settings in it"""

        config = configparser.RawConfigParser()
        config.read(CONFIG_PATH)
        for section in config.sections():
            for key in config[section]:
                try:
                    self.settings[key] = config.get(section, key)
                except Exception as e:
                    print("ERROR - with configuration file at {0} failed with error {1}".format(CONFIG_PATH, e))
                    sys.exit(1)

        # set empty tokens if one is not found on the config
        if 'shodan_token' not in self.settings:
            self.settings['shodan_token'] = ''
        if 'securitytrails_token' not in self.settings:
            self.settings['securitytrails_token'] = ''
        if 'zoomeye_token' not in self.settings:
            self.settings['zoomeye_token'] = ''
        
        return self.settings
