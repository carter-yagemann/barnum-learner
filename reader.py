#!/usr/bin/env python

import logger
import logging
import utils
from os import path, fdopen, remove, listdir
import tempfile
import gzip
import subprocess
from datetime import datetime
import shutil
import redis
from redis_lock import Lock

module_name = 'Reader'

def parse_pt_dir(root):
    """ Parses a directory containing PT traces and meta data. This parser expects the
        following layout:

    root/
        <pdf_hash>/
            info.txt
            mapping.txt[.gz]
            trace_0[.gz]
        [...]

    info.txt should contain two lines: the original filename and the ground truth label.
    mapping.txt (or optionally mapping.txt.gz if gzip compression is used) is the output
        of the volatility plugin psscan.
    trace_0 (or optionally trace_0.gz if gzip compression is used) is a raw PT trace.

    Returns:
    An array where each item contains the following information in dictionary form: directory,
        trace filepath, memory mapping filepath, info filepath, original filename, and label.
        Upon error, None is returned.
    """
    if not path.isdir(root):
        logger.log_error(module_name, str(root) + ' is not a directory')
        return None

    res = []
    entries = listdir(root)

    for entry in entries:

        entry_info = {'base_dir': path.join(root, entry)}

        if not path.isdir(entry_info['base_dir']):
            logger.log_debug(module_name, 'Skipping ' + str(entry) + ' because it is not a directory')
            continue

        entry_contents = listdir(entry_info['base_dir'])
        for file in entry_contents:
            if file == 'info.txt':
                entry_info['info_filepath'] = path.join(entry_info['base_dir'], file)
                with open(entry_info['info_filepath'], 'r') as ifile:
                    entry_info['original_filename'] = ifile.readline().strip()
                    entry_info['label'] = ifile.readline().strip()
            elif file == 'mapping.txt' or file == 'mapping.txt.gz':
                entry_info['mapping_filepath'] = path.join(entry_info['base_dir'], file)
            elif file == 'trace_0' or file == 'trace_0.gz':
                entry_info['trace_filepath'] = path.join(entry_info['base_dir'], file)

        if len(entry_info.keys()) != 6:
            logger.log_warning(module_name, 'Could not find all the necessary files in ' + str(root) + ' skipping')
            logger.log_debug(module_name, 'Found keys: ' + str(entry_info.keys()))
        else:
            logger.log_debug(module_name, 'Adding entry with keys: ' + str(entry_info.keys()))
            res.append(entry_info)

    return res

def read_memory_file(filepath):
    """ Reads a memory file (may be gzipped) and produces an array that can be passed to
        disasm_pt_file() as the mem_map argument.
    """
    if type(filepath) != str:
        logger.log_error(module_name, "Parameter filepath must be a string")
        return None

    if not path.isfile(filepath):
        logger.log_error(module_name, str(filepath) + " does not exist")
        return None

    # Decompress file if necessary
    if filepath[-3:] == '.gz':
        ifile = gzip.open(filepath, 'r')
    else:
        ifile = open(filepath, 'r')

    # Parse lines
    start_time = datetime.now()
    res = []
    for line in ifile:
        try:
            start_addr = int(line[30:48], 16)
        except:
            continue
        filename = line[69:].strip()
        res.append((start_addr, 0, filename))
    # The volatility plugin psscan is dump and only records the starting address of each virtual memory area.
    # It's too late to change this now though, so a hack to get around not knowing the end address is to peek
    # at the starting address of the next memory area. The last memory area's end address will just be the max
    # address.
    sorted_res = sorted(res, key=lambda tuple: tuple[0])
    final_res = []
    for index in range(len(sorted_res) - 1):
        end_addr = sorted_res[index + 1][0] - 1
        final_res.append((sorted_res[index][0], end_addr, sorted_res[index][2]))
    final_res.append((sorted_res[-1][0], 0xFFFFFFFFFFFFFFFF, sorted_res[-1][2]))
    delta_time = datetime.now() - start_time
    logger.log_debug(module_name, 'Parsed ' + str(filepath) + ' in ' + str(delta_time))

    return final_res

def get_source_file(addr, memory):
    for tuple in memory:
        if addr >= tuple[0] and addr <= tuple[1]:
            return tuple
    return None

def init_bbids(host, port, db):
    """ Initializes bbids, which is needed for methods like disasm_pt_file().

    Keywork arguments:
    host -- The hostname for a Redis database.
    port -- The port number for a Redis database.
    db -- The database number for a Redis database.

    Returns:
    True if everything initialized successfully, otherwise False.
    """
    global bbids

    try:
        conn = redis.StrictRedis(host=host, port=port, db=db)
        conn.setnx('counter', 0)
    except:
        logger.log_error(module_name, 'Failed to open connection to Redis server')
        return False

    bbids = {'dict': dict(), 'conn': conn}
    return True

def get_bbid(addr, mem_map):
    """ Normalizes the destination address using the memory mapping and then converts
        it into a unique BBID.

    Keyword arguments:
    addr -- Address to get the BBID for.
    mem_map -- A linear array of tuples in the form (start_address, end_address, source_file).
    """
    global bbids
    lock_name = 'BBIDsLock'

    map = get_source_file(addr, mem_map)
    if map is None:
        return None # Failed to find memory region this address belongs to
    offset = str(addr - map[0])
    key = map[2] + ':' + offset
    if not key in bbids['dict']:
        # Key not in local dictionary, check remote database
        if bbids['conn'].exists(key):
            bbids['dict'][key] = int(bbids['conn'].get(key), 10)
        else:
            # Key not in remote database either, need to assign it a BBID
            with Lock(bbids['conn'], lock_name):
                if not bbids['conn'].exists(key):
                    # Key wasn't created while waiting for write lock, still need to assign BBID
                    bbids['conn'].set(key, bbids['conn'].incr('counter'))
                bbids['dict'][key] = int(bbids['conn'].get(key), 10)

    return bbids['dict'][key]

def warn_and_debug(has_warned, warning, debug):
    """ Prints a debug message and also generates a generic warning message if one hasn't
        been produced before.

    The point is so we know there were problems without spamming the warning log level.
    """
    if not has_warned:
        logger.log_warning(module_name, warning)
        has_warned = True

    logger.log_debug(module_name, debug)

    return has_warned

def disasm_pt_file(trace_path, bin_path, mem_map):
    """ Disassembles a PT trace into instructions and yields (source BBID, target BBID, transfer instruction).

    Source BBID is the BB from which a transfer is happening.
    Target BBID is the BB the transfer ends up in.
    Transfer instruction is the instruction that causes the transfer from source to target (e.g., ret).

    Keyword arguments:
    trace_path -- The filepath to a raw PT trace (may be gzipped).
    bin_path -- The path to a directory containing binaries for use by the disassembler.
    mem_map -- A linear array of tuples in the form (start_address, end_address, source_file).

    Yields:
    (source BBID, target BBID, transfer instruction) until EoF is reached, after which None is yielded.
    """
    ptxed_path = utils.lookup_bin('ptxed')
    if ptxed_path == '':
        logger.log_error(module_name, 'ptxed not found, cannot read ' + str(trace_path))
        return

    if not path.isfile(trace_path):
        logger.log_error(module_name, str(trace_path) + " does not exist or is not a file")
        return

    if not path.isdir(bin_path):
        logger.log_error(module_name, str(trace_path) + " does not exist or is not a directory")
        return

    temp_dir = tempfile.mkdtemp()

    # If file is gzipped, it must be decompressed first
    if trace_path[-3:] == '.gz':
        ifilepath = path.join(temp_dir, 'pt_data')
        logger.log_debug(module_name, 'Decompressing ' + str(trace_path) + ' into ' + str(ifilepath))
        start_time = datetime.now()
        with gzip.open(trace_path, 'rb') as cfile:
            with open(ifilepath, 'wb') as ofile:
                ofile.write(cfile.read())
        delta_time = datetime.now() - start_time
        logger.log_debug(module_name, 'Decompressing ' + str(trace_path) + ' completed in ' + str(delta_time))
    else:
        ifilepath = trace_path

    # Use ptxed to generate tuples
    command = [ptxed_path, '--block:show-blocks']
    for map in mem_map:
        start_addr = hex(map[0])
        filename = path.basename(map[2].replace("\\", '/'))
        binpath = path.join(bin_path, filename)
        if not path.isfile(binpath):
            logger.log_warning(module_name, binpath + ' does not exist')
            continue
        command.append('--raw')
        command.append(binpath + ':' + start_addr)
    command.append('--pt')
    command.append(ifilepath)

    logger.log_debug(module_name, 'Running ' + ' '.join(command))
    start_time = datetime.now()
    warning_msg = 'Non-critical problems while disasm trace, see debug level (-l) for more info'
    has_warned = False
    count = 0
    last_bbid = 0
    last_instr = None

    ptxed = subprocess.Popen(command, stdout=subprocess.PIPE)

    while True:
        line = ptxed.stdout.readline()

        # Metadata lines start with an [ and we want to skip all these except '[block]'
        while len(line) >= 2 and line[0] == '[' and line[1] != 'b':
            line = ptxed.stdout.readline()

        if line == '':
            break # EoF

        if '[block]' == line[:7]:
            # We're moving between basic blocks. The last instruction was the end of the
            # previous basic block and the next instruction is the start of the next.
            line = ptxed.stdout.readline()
            if last_instr is None:
                # The first basic block doesn't have a previous block, skip it
                last_instr = line
                continue
            # Extract the type from the previous instruction (e.g., ret)
            src_parts = last_instr.split(' ')
            if len(src_parts) >= 3:
                src_type = src_parts[2]
            else:
                has_warned = warn_and_debug(has_warned, warning_msg, 'Cannot extract type from: ' + str(src_parts))
                last_instr = line
                continue # bail out
            # Extract the raw address of the next instruction
            dst_addr = int(line.split(' ')[0], 16)
            # Convert the target address into a BBID
            dst_bbid = get_bbid(dst_addr, mem_map)
            if not dst_bbid is None:
                yield (last_bbid, dst_bbid, src_type)
                last_bbid = dst_bbid
                count += 1
            else:
                has_warned = warn_and_debug(has_warned, warning_msg, 'Cannot find BBID for address ' + hex(dst_addr))
                pass # bail out

        last_instr = line

    delta_time = datetime.now() - start_time
    logger.log_info(module_name, 'Generated ' + str(count) + ' entries in ' + str(delta_time))

    # Cleanup temp dir
    shutil.rmtree(temp_dir)

    # End of generator
    while True:
        yield None

def test_reader():
    from sys import argv, exit
    import traceback

    if len(argv) < 7:
        print argv[0], '<input_file>', '<memory_file>', '<bin_dir>', '<redis_host>', '<redis_port>', '<redis_db>'
        exit(0)

    logger.log_start(logging.DEBUG)

    try:
        ofile = tempfile.mkstemp(text=True)
        ofilefd = fdopen(ofile[0], 'w')

        mem_map = read_memory_file(argv[2])
        if not init_bbids(argv[4], argv[5], argv[6]):
            logger.log_error(module_name, 'Failed to initialize database connection')
            exit(1)

        for tuple in disasm_pt_file(argv[1], argv[3], mem_map):
            if tuple is None:
                break
            ofilefd.write(str(tuple) + "\n")

        ofilefd.close()
    except:
        traceback.print_exc()
        ofilefd.close()
        remove(ofile[1])
        logger.log_stop()
        exit(1)

    logger.log_info(module_name, 'Wrote generated tuples to ' + str(ofile[1]))
    logger.log_stop()

if __name__ == '__main__':
    test_reader()
