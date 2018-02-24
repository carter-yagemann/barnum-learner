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
        read_pt_file() as the memory argument.
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

def encoding_from_memory(memory):
    """ Generates an encoding based on a memory mapping produced by read_memory_file().
    """
    start_time = datetime.now()
    res = []
    for tuple in memory:
        name = tuple[2]
        if not name in res:
            res.append(name)
    delta_time = datetime.now() - start_time
    logger.log_debug(module_name, 'Generated encoding from memory in ' + str(delta_time))
    return res

def get_source_file(addr, memory):
    for tuple in memory:
        if addr >= tuple[0] and addr <= tuple[1]:
            return tuple
    return None

def get_encoding(source_filename, offset, encoding):
    try:
        high_bits = encoding.index(source_filename)
        low_bits = offset
        return (high_bits << 48) | low_bits
    except:
        return None

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

def read_pt_file(filepath, memory, encoding, tip_only=False):
    """ Reads a file located at filepath and yields values that are normalized based on
        the provided encoding. Specifically, each address is compared against memory to
        find the source file it belongs to and then that source file is compared against
        encoding to produce a unique value where the upper 16 bits are a unique ID for
        the file and the lower 48 bits are the offset within that file.

    For example, if memory shows address 0x1234 belongs to file 'foo.dll' and its memory
    segment starts at address 0x0 and encoding shows 'foo.dll' unique ID is 1, the
    resulting unique value will be 0x0001000000001234.

    In the case where an address doesn't map to a file, it is simply encoded as
    0xFFFF000000000000 | address.

    If the file doesn't map to an encoding, then a warning is logged because the encoding
    is incomplete and the PT packet is skipped.

    Keyword arguments:
    filepath -- The path to a raw PT or gzipped raw PT file.
    memory -- A linear array of tuples in the form (start_address, end_address, source_file).
    For example: (0x73fd0000, 0x74fd0000, '\Windows\SysWOW64\winmm.dll').
    encoding -- A linear array of filenames. The index of the filename represents a unique and
    consistent identifier for this file.
    tip_only -- Only use TIP packets, ignore TNT.

    Yields:
    Encoded values as integers until EOF is reached, after which None is yielded.
    """
    ptdump_path = utils.lookup_bin('ptdump')
    if ptdump_path == '':
        logger.log_error(module_name, 'ptdump not found, cannot read ' + str(filepath))
        return

    if type(filepath) != str:
        logger.log_error(module_name, "Parameter filepath must be a string")
        return

    if not path.isfile(filepath):
        logger.log_error(module_name, str(filepath) + " does not exist")
        return

    if type(memory) != list or type(encoding) != list:
        logger.log_error(module_name, "Parameters memory and encoding must be lists")
        return

    temp_dir = tempfile.mkdtemp()

    # If file is gzipped, it must be decompressed first
    if filepath[-3:] == '.gz':
        ifilepath = path.join(temp_dir, 'pt_data')
        logger.log_debug(module_name, 'Decompressing ' + str(filepath) + ' into ' + str(ifilepath))
        start_time = datetime.now()
        with gzip.open(filepath, 'rb') as cfile:
            with open(ifilepath, 'wb') as ofile:
                ofile.write(cfile.read())
        delta_time = datetime.now() - start_time
        logger.log_debug(module_name, 'Decompressing ' + str(filepath) + ' completed in ' + str(delta_time))
    else:
        ifilepath = filepath

    # Use ptdump to generate tuples
    command = [ptdump_path, '--no-pad', '--no-timing', '--no-cyc', '--no-offset', '--lastip', ifilepath]
    logger.log_debug(module_name, 'Running ' + ' '.join(command))
    start_time = datetime.now()
    count = 0
    last_addr = 0
    warning_msg = 'Non-critical problems while reading trace, see debug level (-l) for more info'
    has_warned = False
    ptdump = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in ptdump.stdout:
        parts = line.split(' ')
        packet_type = parts[0]
        if packet_type == 'tip':
            if parts[-1].strip() == '<suppressed>':
                continue
            try:
                last_addr = int(parts[-1], 16)
            except:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to convert ' + str(parts[-1]) + ' to int in ' + filepath)
                continue

            mapping = get_source_file(last_addr, memory)
            if mapping is None:
                yield 0xFFFF000000000000 | last_addr
                continue

            value = get_encoding(mapping[2], last_addr - mapping[0], encoding)
            if value is None:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to find encoding for ' + str(mapping[2]) + ' in ' + filepath)
                continue

            yield value
            count += 1

        elif not tip_only and packet_type == 'tnt.8':
            tnts = parts[-1].strip()
            mapping = get_source_file(last_addr, memory)
            if mapping is None:
                yield 0xFFFF000000000000 | last_addr
                continue

            value = get_encoding(mapping[2], 0, encoding)
            if value is None:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to find encoding for ' + str(mapping[2]) + ' in ' + filepath)
                continue

            for tnt in tnts:
                if tnt == '!':
                    yield value
                    count += 1
                elif tnt == '.':
                    yield value + 1
                    count += 1
                else:
                    has_warned = warn_and_debug(has_warned, warning_msg,
                            'Unexpected TNT value ' + str(tnt) + ' in ' + filepath)
                    continue

        # These packet types don't yield anything, but are needed to keep track of last IP
        elif packet_type == 'fup':
            if parts[-1].strip() == '<suppressed>':
                continue
            try:
                last_addr = int(parts[-1], 16)
            except:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to convert ' + str(parts[-1]) + ' to int in ' + filepath)
                continue
        elif packet_type == 'tip.pge':
            if parts[-1].strip() == '<suppressed>':
                continue
            try:
                last_addr = int(parts[-1], 16)
            except:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to convert ' + str(parts[-1]) + ' to int in ' + filepath)
                continue
        elif packet_type == 'tip.pgd':
            if parts[-1].strip() == '<suppressed>':
                continue
            try:
                last_addr = int(parts[-1], 16)
            except:
                has_warned = warn_and_debug(has_warned, warning_msg,
                        'Failed to convert ' + str(parts[-1]) + ' to int in ' + filepath)
                continue

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
    if len(argv) < 3:
        print argv[0], '<input_file>', '<memory_file>'
        exit(0)

    logger.log_start(logging.DEBUG)

    try:
        ofile = tempfile.mkstemp(text=True)
        ofilefd = fdopen(ofile[0], 'w')

        memory = read_memory_file(argv[2])
        encoding = encoding_from_memory(memory)

        for tuple in read_pt_file(argv[1], memory, encoding):
            if tuple is None:
                break
            ofilefd.write(str([hex(x) for x in res]) + "\n")

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
