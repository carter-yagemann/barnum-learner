#!/usr/bin/env python
#
# Copyright 2018 Carter Yagemann
#
# This file is part of Barnum.
#
# Barnum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Barnum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Barnum.  If not, see <https://www.gnu.org/licenses/>.

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
