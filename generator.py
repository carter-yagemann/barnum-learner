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

from __future__ import print_function

import logger
import logging
import reader
import filters
from multiprocessing import Process, Queue, Value
from datetime import datetime
import os
import sys
import traceback
from copy import deepcopy
from time import sleep
if sys.version_info.major <= 2:
    from Queue import Empty
else:
    from queue import Empty

module_name = 'Generator'

gen_workers = []
in_service = []
running = Value('b', False)
fin_tasks = Value('i', 0)

def start_generator(num_workers, target, res_queue_max=1000, seq_len=1):
    """ Starts up a generator for dispatching jobs to the target function.

    Once started, arrays of arguments (jobs) can be appended to the job queue and the
    workers will invoke the function target with them and place the results in the
    results queue. The first item in the job is special and is *not* passed as an
    argument to target. Instead, it is returned along with the target's results. This
    allows context info (like a label) to be returned along with the results. In other
    words, the formatting is:

        Job: [context, arg1, arg2, arg3, ...]
        Res: [context, result]

    Note that if seq_len is 1, result is whatever type target returns. For sequence
    lengths greater than 1, result is an array where each item is the type target returns.

    Keyword arguments:
    num_workers -- The number of workers to spawn for processing jobs.
    target -- The function to invoke.
    res_queue_max -- The max size of the results queue. Once full, workers will wait for space.
    seq_len -- Target is assumed to be a generator function, so workers will combine seq_len yielded
    values into an array before placing it on the results queue.
    connection will be established, meaning workers can only use preprocessed traces.

    Returns:
    A queue for submitting jobs (job_queue) and a queue for getting results (res_queue).
    """
    global job_queue, res_queue, gen_workers, running, in_service

    # Initialize queues and spawn workers
    job_queue = Queue()
    res_queue = Queue(res_queue_max)
    running.value = True
    fin_tasks.value = 0
    for id in range(num_workers):
        in_service.append(Value('b', False))
        worker_args = (target, job_queue, res_queue, running, in_service[id], int(seq_len))
        worker = Process(target=worker_loop, args=worker_args)
        gen_workers.append(worker)
        worker.start()

    return (job_queue, res_queue)

def stop_generator(timeout=10):
    global module_name
    global gen_workers
    global running
    global in_service

    # Signal workers that there's no more jobs coming
    running.value = False
    for worker in gen_workers:
        if worker.is_alive():
            for sec in range(timeout):
                sleep(1)
                if not worker.is_alive():
                    continue
            if worker.is_alive():
                logger.log_debug(module_name, 'Timeout to join worker exceeded, forcefully terminating')
                worker.terminate()
    gen_workers = []
    in_service = []

def get_in_service():
    global in_service

    count = 0
    for worker in in_service:
        if worker.value:
            count += 1

    return count

def worker_loop(target, job_queue, res_queue, running, in_service, seq_len=1):
    """ Main worker loop, gets data from the target generator and chunks it into sequences.

    Sequences are generated in a sliding window fashion. For example, if the data is
    A, B, C, D, and seq_len is 2, the worker will yield:

        A, B
        B, C
        C, D
        ...
    """
    global module_name
    m_pid = os.getpid()

    logger.log_debug(module_name, 'Worker ' + str(m_pid) + ' spawned with sequence length ' + str(seq_len))

    while True:
        try:
            job = job_queue.get(True, 5)
        except Empty:
            if running.value:
                continue
            else:
                logger.log_debug(module_name, 'Worker ' + str(os.getpid()) + ' returned')
                return
        except KeyboardInterrupt:
            return

        in_service.value = True
        logger.log_debug(module_name, 'Starting job in worker ' + str(m_pid))
        start_time = datetime.now()

        try:
            seq = []
            for output in target(*(job[1:])):
                if output is None:        # End of generator
                    break

                curr_size = len(seq)      # Sequence generation
                if curr_size < (seq_len - 1):
                    seq.append(output[0])
                elif curr_size == (seq_len - 1):
                    seq.append(output[0])
                    # We only want to send sequences that end in an indirect control flow transfer
                    if True in [func(output) for func in filters.enabled_filters]:
                        res_queue.put([job[0], deepcopy([output[1]] + seq)])
                else:
                    seq.pop(0)
                    seq.append(output[0])
                    # We only want to send sequences that end in an indirect control flow transfer
                    if True in [func(output) for func in filters.enabled_filters]:
                        res_queue.put([job[0], deepcopy([output[1]] + seq)])
        except KeyboardInterrupt:
            pass
        except:
            logger.log_error(module_name, 'Error while processing job in worker ' + str(m_pid) + "\n" + str(traceback.format_exc()))

        logger.log_debug(module_name, 'Finished job in worker ' + str(m_pid) + ' in ' + str(datetime.now() - start_time))
        with fin_tasks.get_lock():
            fin_tasks.value += 1
        in_service.value = False

def test_generator():
    from sys import argv, exit
    import reader
    import tempfile

    if len(argv) < 5:
        print(argv[0], '<input_file>', '<bin_dir>', '<memory_file>', '<seq_len>')
        exit(0)

    logger.log_start(logging.DEBUG)

    try:
        ofile = tempfile.mkstemp(text=True)
        ofilefd = os.fdopen(ofile[0], 'w')

        filters.set_filters(['ret'])
        memory = reader.read_memory_file(argv[3])

        input, output = start_generator(2, reader.disasm_pt_file, seq_len=int(argv[4], 10))
        input.put((None, argv[1], argv[2], memory))
        while True:
            try:
                res = output.get(True, 5)
            except:
                count = get_in_service()
                if get_in_service() == 0:
                    break
                else:
                    logger.log_debug(module_name, str(count) + ' workers still working on jobs')
                    continue
            ofilefd.write(str(res[0]) + ": " + str(res[1]) + "\n")

        stop_generator(10)
        ofilefd.close()
    except:
        traceback.print_exc()
        ofilefd.close()
        os.remove(ofile[1])
        logger.log_stop()
        exit(1)

    logger.log_info(module_name, 'Wrote generated tuples to ' + str(ofile[1]))
    logger.log_stop()

if __name__ == '__main__':
    test_generator()
