#!/usr/bin/env python

import sys
import os
import reader
import logger
import numpy as np

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

    if len(sys.argv) != 6:
        sys.stdout.write('Usage: ' + sys.argv[0] + ' <pt_trace> ' + '<mem_map> ' + '<bin_dir> ' + '<max_sequence_length> ' + '<output_file>' + "\n")
        sys.exit(1)

    trace_filepath = sys.argv[1]
    mem_filepath = sys.argv[2]
    bin_dir = sys.argv[3]
    max_seq = int(sys.argv[4])
    opath = sys.argv[5]

    # Input validation
    if not os.path.isfile(trace_filepath):
        sys.stderr.write('Error: ' + str(trace_filepath) + " either does not exist or is not a file\n")
        sys.exit(1)

    if not os.path.isfile(mem_filepath):
        sys.stderr.write('Error: ' + str(mem_filepath) + " either does not exist or is not a file\n")
        sys.exit(1)

    if not os.path.isdir(bin_dir):
        sys.stderr.write('Error: ' + str(bin_dir) + " either does not exist or is not a directory\n")
        sys.exit(1)

    # Initialization
    logger.log_start(20)
    mem_map = reader.read_memory_file(mem_filepath)
    history = list() # History of past basic blocks

    # edges is a three-level dictionary where the keys for the first layer are sequence length,
    # the keys for the second layer are source BBID(s), and the keys for the third layer is
    # destination BBID. The value is count (i.e., how many times that (src, dst) pair has occurred.
    edges = dict()
    for seq_len in range(1, max_seq + 1):
        edges[seq_len] = dict()

    # Disassembly
    logger.log_info(module_name, 'Disassembling trace')
    for tuple in reader.disasm_pt_file(trace_filepath, bin_dir, mem_map):
        if tuple is None:
            break # End of trace

        src_bbid, dst_bbid, instr = tuple

        # Update history
        history.append(src_bbid)
        if len(history) > max_seq:
            history.pop(0)

        if not 'ret' in instr:
            continue # Only care about counting ret control-flow transfers for now

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
