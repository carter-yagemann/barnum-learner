#!/usr/bin/env python

import logger
import os

module_name = 'Utils'

def lookup_bin(name):
    """ Looks up the path to a bin using Linux environment variables.

    Not as robust as a program like which, but should be good enough.
    """
    logger.log_debug(module_name, 'PATH = ' + str(os.environ['PATH']))
    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, name)
        if os.path.isfile(candidate):
            return candidate
    logger.log_warning(module_name, 'Failed to find ' + str(name))
    return '' # Failed to find a match
