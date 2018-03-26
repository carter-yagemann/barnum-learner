#!/usr/bin/env python

import logger
import logging

module_name = 'Filters'

available_filters = {
    'ret': (lambda x: x[2] == 'ret'),
    'call': (lambda x: x[2] == 'call'),
    'icall': (lambda x: x[4] >= 2 and x[3][0] == 'call' and 'ptr' in x[3][1:]),
    'jmp': (lambda x: x[2] == 'jmp'),
    'ijmp': (lambda x: x[4] >= 2 and x[3][0] == 'jmp' and 'ptr' in x[3][1:])
}

enabled_filters = list()

def clear_filters():
    """ Clears all currently enabled filters. """
    enabled_filters = list()

def add_filter(key):
    """ Adds a filter from the available_filters dictionary. """
    if key in available_filters.keys():
        enabled_filters.append(available_filters[key])
    else:
        logger.log_warning(module_name, str(key) + " not in available filters")

def add_custom_filter(filter):
    """ Adds a custom filter to the enabled filters list.

    This filter should be a lambda function that returns True or False.
    """
    enabled_filters.append(filter)

def set_filters(keys):
    """ Enables filters using the provided list of keys to reference available_filters. """
    clear_filters()
    for key in keys:
        add_filter(key)

def get_num_enabled():
    """ Returns the number of filters currently enabled. """
    return len(enabled_filters)
