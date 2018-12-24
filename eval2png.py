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

import sys
import os
import logging
import logger
import gzip
from optparse import OptionParser
import png
import numpy as np

module_name = 'Eval2PNG'
module_version = '1.0.0'

# Error Codes
ERROR_INVALID_ARG = 1
ERROR_RUNTIME     = 2

def parse_eval(ifilepath, width):
    with gzip.open(ifilepath, 'rt') as ifile:
        try:
            parts = [line.strip().split(',') for line in ifile.readlines()]
            accuracy = [int(part[0]) for part in parts]
        except (IOError, EOFError):
            logger.log_error(module_name, 'Failed to parse ' + ifilepath)
            return

    # Padding
    if len(accuracy) % width != 0:
        accuracy += [1] * (width - len(accuracy) % width)

    # Boxed row, flat pixel, 1 bit depth, greyscale representation
    return np.reshape(np.array(accuracy), (-1, width))

def main():
    parser = OptionParser(usage='Usage: %prog [options] eval_file output_png', version='Barnum Eval2PNG ' + module_version)
    parser.add_option('-f', '--force', action='store_true',
                      help='If output PNG filepath already exists, overwrite it')
    parser.add_option('-w', '--width', action='store', type='int', default=4096,
                      help='Width of output image (default: 4096)')

    options, args = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        sys.exit(ERROR_INVALID_ARG)

    eval_file, output_file = args

    # Input validation
    if not os.path.isfile(eval_file):
        sys.stderr.write(eval_file + " is not a file or does not exist\n")
        sys.exit(ERROR_INVALID_ARG)
    if os.path.exists(output_file) and not options.force:
        sys.stderr.write(output_file + " already exists, use --force to overwrite\n")
        sys.exit(ERROR_INVALID_ARG)
    if os.path.exists(output_file) and options.force and not os.path.isfile(output_file):
        sys.stderr.write(output_file + " is not a file, it cannot be overwritten\n")
        sys.exit(ERROR_INVALID_ARG)

    logger.log_start(20)
    logger.log_info(module_name, 'Barnum Eval2PNG ' + module_version)

    logger.log_info(module_name, 'Parsing ' + eval_file)
    try:
        data = parse_eval(eval_file, options.width)
    except Exception as ex:
        logger.log_error(module_name, "Unexpected exception: " + str(ex))
        logger.log_stop()
        sys.exit(ERROR_RUNTIME)

    if data is None:
        logger.log_error(module_name, "Failed to parse evaluation file")
        logger.log_stop()
        sys.exit(ERROR_RUNTIME)

    logger.log_info(module_name, 'Saving PNG to ' + output_file)
    try:
        png.from_array(data, 'L;1').save(output_file)
    except Exception as ex:
        logger.log_error(module_name, "Unexpected exception: " + str(ex))
        logger.log_stop()
        sys.exit(ERROR_RUNTIME)

    logger.log_stop()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("Caught keyboard interrupt, exiting...\n")
        sys.exit(ERROR_INVALID_ARG)
