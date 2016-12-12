# -*- coding: utf-8 -*-
import copy
import logging
import os

import yaml
import yaml.scanner
from staticconf.loader import yaml_loader

# Required global (config.yaml) and local (rule.yaml)  configuration options
required_globals = frozenset(['es_host', 'es_port', 'writeback'])

base_config = {}

def load_config(args):
    """ Creates a conf dictionary for ElastAlerter. Loads the global
    config file and then each rule found in rules_folder.

    :param args: The parsed arguments to ElastAlert
    :return: The global configuration, a dictionary.
    """
    names = []
    filename = args.config
    conf = yaml_loader(filename)

    # Make sure we have all required globals
    if required_globals - frozenset(conf.keys()):
        raise EAException('%s must contain %s' % (filename, ', '.join(required_globals - frozenset(conf.keys()))))

    conf.setdefault('max_query_size', 10000)
    conf.setdefault('scroll_keepalive', '30s')
    conf.setdefault('disable_rules_on_error', True)
    conf.setdefault('scan_subdirectories', True)

    global base_config
    base_config = copy.deepcopy(conf)

    return conf
