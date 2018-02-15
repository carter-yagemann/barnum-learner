#!/usr/bin/env python

import logger
import logging
from multiprocessing import Process, Queue, Value
from datetime import datetime
import os
import traceback
from copy import deepcopy

module_name = 'Generator'

gen_workers = []
in_service = []
running = Value('b', False)

def start_generator(num_workers, target, res_queue_max=1000, seq_len=1, sliding_window=True):
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
    seq_len -- target is assumed to be a generator function, so workers will combine seq_len yielded
    values into an array before placing it on the results queue.
    sliding_window -- Use sliding window. See worker_loop for more details.

    Returns:
    A queue for submitting jobs (job_queue) and a queue for getting results (res_queue).
    """
    global job_queue
    global res_queue
    global gen_workers
    global running
    global in_service

    # Initialize queues and spawn workers
    job_queue = Queue()
    res_queue = Queue(res_queue_max)
    running.value = True
    for id in range(num_workers):
        in_service.append(Value('b', False))
        worker = Process(target=worker_loop, args=(target, job_queue, res_queue, running, in_service[id],
                                                   int(seq_len), sliding_window))
        gen_workers.append(worker)
        worker.start()

    return (job_queue, res_queue)

def stop_generator(timeout=None):
    global module_name
    global gen_workers
    global running
    global in_service

    # Signal workers that there's no more jobs coming
    running.value = False
    for worker in gen_workers:
        try:
            worker.join(timeout)
        except:
            logger.log_warning(module_name, 'Timeout to join worker exceeded, forcefully terminating')
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

def worker_loop(target, job_queue, res_queue, running, in_service, seq_len=1, sliding_window=True):
    """ Main worker loop, gets data from the target generator and chunks it into sequences.

    By default, sequences are generated in a sliding window fashion. For example, if the data is
    A, B, C, D, and seq_len is 2, the worker will yield:

        A, B
        B, C
        C, D
        ...

    If sliding_window is False, then the generated sequences would be:

        A, B
        C, D
        ...
    """
    global module_name
    m_pid = os.getpid()

    logger.log_debug(module_name, 'Worker ' + str(m_pid) + ' spawned with sequence length ' + str(seq_len))

    while True:
        try:
            job = job_queue.get(True, 5)
        except:
            if running.value:
                continue
            else:
                logger.log_debug(module_name, 'Worker ' + str(os.getpid()) + ' returned')
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
                    seq.append(output)
                elif curr_size == (seq_len - 1):
                    seq.append(output)
                    res_queue.put([job[0], deepcopy(seq)])
                    if not sliding_window:
                        seq = []
                else:
                    seq.pop(0)
                    seq.append(output)
                    res_queue.put([job[0], deepcopy(seq)])
        except:
            logger.log_error(module_name, 'Error while processing job in worker ' + str(m_pid) + "\n" + str(traceback.format_exc()))

        logger.log_debug(module_name, 'Finished job in worker ' + str(m_pid) + ' in ' + str(datetime.now() - start_time))
        in_service.value = False

def test_generator():
    from sys import argv, exit
    import reader
    import tempfile

    if len(argv) < 4:
        print argv[0], '<input_file>', '<memory_file>', '<seq_len>'
        exit(0)

    logger.log_start(logging.DEBUG)

    try:
        ofile = tempfile.mkstemp(text=True)
        ofilefd = os.fdopen(ofile[0], 'w')

        memory = reader.read_memory_file(argv[2])
        encoding = reader.encoding_from_memory(memory)
        label = 0 # Just an arbitrary label for testing functionality

        input, output = start_generator(2, reader.read_pt_file, seq_len=int(argv[3], 10))
        input.put((label, argv[1], memory, encoding))
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
            ofilefd.write(str(res[0]) + ": " + str([hex(x) for x in res[1]]) + "\n")

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
