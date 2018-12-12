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
import logging
import sys
import os
import reader
import gzip
from optparse import OptionParser, OptionGroup
from struct import pack, unpack

module_name = 'Preprocess'
fmt_str = "QQBBB"

def unpack_instr(instr):
    """Unpacks an instruction that was written to file"""
    parts = unpack(fmt_str, instr[:19])
    s_str = instr[19:19 + parts[2]]
    l_str = instr[19 + parts[2]:]
    return (parts[0], parts[1], s_str.decode(), l_str.decode().split(' '), parts[4])

def pack_instr(instr):
    """Packs an instruction for writing to file"""
    i_str = ' '.join(instr[3]).encode('utf-8')
    s_str = instr[2].encode('utf-8')
    packed = pack(fmt_str, instr[0], instr[1], len(s_str), len(i_str), instr[4]) + s_str + i_str
    return pack("H", len(packed)) + packed

def main():
    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] trace_directory bin_directory')
    parser.add_option('-f', '--force', action='store_true',
                      help='If a complete or partial output already exists, overwrite it.')
    parser.add_option('-t', '--timeout', action='store', type='int', default=None,
                      help='Max seconds to run before quitting (default: infinite).')
    options, args = parser.parse_args()

    if len(args) < 2:
        parser.print_help()
        sys.exit(0)

    data_dir = args[0]
    bin_dir = args[1]

    logger.log_start(logging.INFO)

    # Input validation
    if not os.path.isdir(data_dir):
        logger.log_error(module_name, 'ERROR: ' + data_dir + ' is not a directory')
        logger.log_stop()
        sys.exit(1)

    if not os.path.isdir(bin_dir):
        logger.log_error(module_name, 'ERROR: ' + bin_dir + ' is not a directory')
        logger.log_stop()
        sys.exit(1)

    # Make sure all the expected files are there
    mem_file = None
    trace_file = None

    files = os.listdir(data_dir)
    for file in files:
        if file == 'mapping.txt' or file == 'mapping.txt.gz':
            mem_file = os.path.join(data_dir, file)
        elif file == 'trace_0' or file == 'trace_0.gz':
            trace_file = os.path.join(data_dir, file)

    if mem_file is None:
        logger.log_error(module_name, 'ERROR: Could not find mapping.txt or mapping.txt.gz in ' + data_dir)
        logger.log_stop()
        sys.exit(1)

    if trace_file is None:
        logger.log_error(module_name, 'ERROR: Could not find trace_0 or trace_0.gz in ' + data_dir)
        logger.log_stop()
        sys.exit(1)

    # Parse the memory file
    mem_map = reader.read_memory_file(mem_file)
    if mem_map is None:
        logger.log_error(module_name, 'ERROR: Failed to parse memory mapping file')
        logger.log_stop()
        sys.exit(1)

    # We're ready to parse the trace
    o_filepath = os.path.join(data_dir, 'trace_parsed.gz')

    if os.path.isfile(o_filepath) and not options.force:
        logger.log_error(module_name, 'ERROR: Preprocess file already exists')
        logger.log_stop()
        sys.exit(1)

    if os.path.isfile(o_filepath + '.part') and not options.force:
        logger.log_error(module_name, 'ERROR: Partial preprocess file already exists')
        logger.log_stop()
        sys.exit(1)

    entries = 0
    with gzip.open(o_filepath + '.part', 'wb') as ofile:
        for instr in reader.disasm_pt_file(trace_file, bin_dir, mem_map, options.timeout):
            if instr is None:
                break
            ofile.write(pack_instr(instr))
            entries += 1

    if entries > 0:
        os.rename(o_filepath + '.part', o_filepath)
    else:
        logger.log_error(module_name, 'ERROR: No output produced, empty file')
        os.remove(o_filepath + '.part')

    logger.log_stop()

if __name__ == '__main__':
    main()
