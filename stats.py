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
import reader
import logger
import numpy as np
import filters
from optparse import OptionParser

module_name = 'Stats'

def insert(seq, dst):
    seq_len = len(seq)
    if seq_len > max_seq:
        logger.log_warning(module_name, 'Tried to insert sequence that exceeds max sequence length')
        return

    src_key = str(seq)

    if src_key in edges[seq_len] and dst in edges[seq_len][src_key]:
        edges[seq_len][src_key][dst] += 1
    elif src_key in edges[seq_len]:
        edges[seq_len][src_key][dst] = 1
    else:
        edges[seq_len][src_key] = dict()
        edges[seq_len][src_key][dst] = 1

def main():
    global edges, max_seq

    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] pt_trace_dir output_file')
    parser.add_option('-r', '--parse-ret', action='store_true', dest='parse_ret',
                      help='Consider returns')
    parser.add_option('-c', '--parse-icall', action='store_true', dest='parse_icall',
                      help='Consider indirect calls')
    parser.add_option('-j', '--parse-ijmp', action='store_true', dest='parse_ijmp',
                      help='Consider indirect jumps')
    parser.add_option('-s', '--sequence-length', action='store', dest='max_seq', type='int', default=32,
                      help='Max sequence length to calculate (default: 32)')

    options, args = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        sys.stdout.write("\n  Note: Only preprocessed traces are supported\n")
        sys.exit(1)

    trace_filepath = os.path.join(args[0], 'trace_parsed.gz')
    opath = args[1]
    max_seq = options.max_seq

    # Input validation
    if not os.path.isfile(trace_filepath):
        sys.stderr.write('Error: ' + str(trace_filepath) + " either does not exist or is not a file\n")
        sys.exit(1)

    if options.parse_ret:
        filters.add_filter('ret')

    if options.parse_icall:
        filters.add_filter('icall')

    if options.parse_ijmp:
        filters.add_filter('ijmp')

    if filters.get_num_enabled() == 0:
        sys.stderr.write("Error: Must specify at least one thing to learn (-r, -c, -j)\n")
        sys.exit(1)

    # Initialization
    logger.log_start(20)
    history = list() # History of past basic blocks

    # edges is a three-level dictionary where the keys for the first layer are sequence length,
    # the keys for the second layer are source BBID(s), and the keys for the third layer is
    # destination BBID. The value is count (i.e., how many times that (src, dst) pair has occurred.
    edges = dict()
    for seq_len in range(1, max_seq + 1):
        edges[seq_len] = dict()

    # Parsing
    logger.log_info(module_name, 'Parsing trace')
    for tuple in reader.read_preprocessed(trace_filepath):
        if tuple is None:
            break # End of trace

        src_bbid, dst_bbid, instr = tuple[:3]

        # Update history
        history.append(src_bbid)
        if len(history) > max_seq:
            history.pop(0)

        if not True in [func(tuple) for func in filters.enabled_filters]:
            continue

        for seq_len in range(1, min(len(history), max_seq) + 1):
            insert(history[-seq_len:], dst_bbid)

    # Distribution of how many possible destinations sources have, up to df_max destinations.
    logger.log_info(module_name, 'Calculating distributions')
    df_max = 100
    df = np.zeros((max_seq, df_max), dtype=int)

    for seq_len in range(1, max_seq + 1):
        for src_bbid in edges[seq_len]:
            dst_size = len(edges[seq_len][src_bbid].keys())
            if dst_size <= df_max:
                df[seq_len - 1][dst_size - 1] += 1
            else:
                df[seq_len - 1][df_max - 1] += 1

    # Save statistics
    logger.log_info(module_name, 'Saving statistics to ' + str(opath))
    with open(opath, 'w') as ofile:
        # Header
        ofile.write('seq_len,' + ','.join([str(x) for x in range(1, df_max + 1)]) + "\n")
        # Data
        for seq_len in range(1, max_seq + 1):
            ofile.write(str(seq_len) + ',' + ','.join([str(x) for x in df[seq_len - 1]]) + "\n")

    # Cleanup
    logger.log_stop()

if __name__ == '__main__':
    main()
