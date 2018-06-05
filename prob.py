#!/usr/bin/env python

import sys
from os import path
import logger
import logging
import reader
import generator
import filters
from optparse import OptionParser, OptionGroup
import numpy as np
import random
from multiprocessing import cpu_count, Pool, Process
from datetime import datetime
import traceback
import tempfile
import gzip
import redis
from Queue import Empty
from functools32 import lru_cache

module_name = 'Prob'

# Exit codes
EXIT_INVALID_ARGS   = 1
EXIT_UNIMPLEMENTED  = 2
EXIT_RUNTIME_ERROR  = 3
EXIT_USER_INTERRUPT = 4

def clean_exit(error_code, message, kill_generator=False):
    """ Performs a clean exit, useful for when errors happen that can't be recovered from."""
    logger.log_critical(module_name, message)
    if kill_generator:
        generator.stop_generator(2)
    logger.log_stop()
    sys.exit(error_code)

def save_sets():
    try:
        with open(options.output_sets, 'w') as ofile:
            for key in sets_meta:
                ofile.write('[' + str(key) + "]\n") # Header
                for item in sets_meta[key]:
                    ofile.write(item['base_dir'] + "\n")
    except:
        logger.log_error(module_name, "Failed to save sets to " + str(options.output_sets))

def load_sets():
    if not path.isfile(options.input_sets):
        clean_exit(EXIT_INVALID_ARGS, "Cannot find file " + str(options.input_sets))

    set_key = None

    try:
        with open(options.input_sets, 'r') as ifile:
            for line in ifile:
                line = line.rstrip()
                if len(line) < 1:
                    continue
                if line[0] == '[':
                    set_key = line[1:-1]
                else:
                    # Line should be the path to a trace directory
                    if not root_dir in line:
                        logger.log_warning(module_name, 'Input data specified with -i must be in ' + str(root_dir) + ', skipping')
                        continue
                    if not path.isdir(line):
                        logger.log_warning(module_name, 'Cannot find directory ' + str(line) + ' to load data from, skipping')
                        continue
                    matches = [record for record in fs if record['base_dir'] == line]
                    if len(matches) < 1:
                        logger.log_warning(module_name, 'Could not find data in directory ' + str(line) + ', skipping')
                        continue
                    if set_key in sets_meta.keys():
                        sets_meta[set_key].append(matches[0])
    except:
        clean_exit(EXIT_RUNTIME_ERROR, "Failed to load sets from " + str(options.input_sets))

def init_prob(flush=False):
    global conn
    random.seed()
    conn = redis.StrictRedis(options.redis_host, options.redis_port, options.redis_db)
    if flush:
        conn.flushdb()

def redis_key(sequence, label):
    return str(sequence) + ":" + str(label)

@lru_cache(maxsize=8192)
def get_weights(sequence):
    global conn

    pipe = conn.pipeline(transaction=False)
    for weight in range(options.max_classes):
        pipe.get(redis_key(sequence, weight))
    reply = pipe.execute()

    res = list()
    for w in reply:
        if w is None:
            res.append(0)
        else:
            res.append(int(w))

    return res

def pick_prob(weights):
    rnd = random.random() * sum(weights)
    for i, w in enumerate(weights):
        rnd -= w
        if rnd < 0:
            return i

def pick_prob_conf(weights):
    total = sum(weights)
    rnd = random.random() * total
    for i, w in enumerate(weights):
        rnd -= w
        if rnd < 0:
            return (i, float(weights[i]) / float(total))

def train_prob(sequence, label):
    """ Trains a prob model."""
    global conn
    key = redis_key(sequence, label)
    conn.incr(key)
    return 0.0

def test_prob(sequence, label):
    """ Tests the current prob model."""
    global conn

    weights = get_weights(str(sequence))
    if sum(weights) == 0:
        # We've never seen this sequence before, so the best we can do is random guess
        predict = random.choice(range(options.max_classes))
    else:
        # Make a prediction based on the current state of the model
        predict = pick_prob(weights)

    if predict == label:
        return 1.0
    else:
        return 0.0

def predict_prob(sequence, label):
    """ Predict using current prob model."""
    global conn

    weights = get_weights(str(sequence))
    if sum(weights) == 0:
        # We've never seen this sequence before, so the best we can do is random guess
        predict = random.choice(range(options.max_classes))
        conf = 1.0 / options.max_classes
    else:
        # Make a prediction based on the current state of the model
        predict, conf = pick_prob_conf(weights)

    return (predict, conf)

def worker_loop(f):
    # Get parsed sequences and feed them to the prob model
    samples = 0
    score = 0.0
    while True:
        try:
            res = oqueue.get(True, 5)
        except Empty:
            in_service = generator.get_in_service()
            if in_service == 0:
                break
            else:
                logger.log_debug(module_name, str(in_service) + ' workers still working on jobs')
                continue
        except KeyboardInterrupt:
            break

        xs = res[1][1:]
        ys = res[1][0] % options.max_classes

        score += f(xs, ys)
        samples += 1

    if samples > 0:
        return score / samples
    else:
        return 0.0

def map_to_model(samples, f):
    """ A helper function because train_on_batch() and test_on_batch() are so similar."""
    global redis_info
    global oqueue

    random.shuffle(samples)
    # There's no point spinning up more worker threads than there are samples
    threads = min(options.threads, len(samples))

    if options.preprocess:
        gen_func = reader.read_preprocessed
    else:
        gen_func = reader.disasm_pt_file

    # When you gonna fire it up? When you gonna fire it up?
    iqueue, oqueue = generator.start_generator(threads, gen_func, options.queue_size, options.seq_len, redis_info)

    for sample in samples:
        if options.preprocess:
            iqueue.put((None, sample['parsed_filepath']))
        else:
            sample_memory = reader.read_memory_file(sample['mapping_filepath'])
            if sample_memory is None:
                logger.log_warning(module_name, 'Failed to parse memory file, skipping')
                continue
            iqueue.put((None, sample['trace_filepath'], bin_dirpath, sample_memory))

    ncpu = cpu_count()
    workers = Pool(ncpu)
    res = workers.map(worker_loop, [f] * ncpu)

    generator.stop_generator(10)

    return sum(res) / len(res)

def train_model(training_set):
    """ Trains the Prob model."""
    start_time = datetime.now()
    map_to_model(training_set, train_prob)
    logger.log_info(module_name, 'Training finished in ' + str(datetime.now() - start_time))

def test_model(testing_set):
    """ Test the Prob model."""
    res = map_to_model(testing_set, test_prob)
    logger.log_info(module_name, 'Results: accuracy ' + str(res))

def eval_worker_loop(temp_dir, sample):
    o_filename = sample['label'] + '-' + path.basename(sample['base_dir']) + '.gz'
    o_filepath = path.join(temp_dir, o_filename)
    logger.log_debug(module_name, 'Writing to ' + o_filepath)
    with gzip.open(o_filepath, 'w') as ofile:
        if options.preprocess:
            gen_func = reader.read_preprocessed
        else:
            gen_func = reader.disasm_pt_file

        iqueue, oqueue = generator.start_generator(1, gen_func, options.queue_size, options.seq_len, redis_info)

        if options.preprocess:
            iqueue.put((None, sample['parsed_filepath']))
        else:
            sample_memory = reader.read_memory_file(sample['mapping_filepath'])
            if sample_memory is None:
                logger.log_warning(module_name, 'Failed to parse memory file, skipping')
                generator.stop_generator(10)
                return
            iqueue.put((None, sample['trace_filepath'], bin_dirpath, sample_memory))

        while True:
            try:
                res = oqueue.get(True, 5)
            except:
                in_service = generator.get_in_service()
                if in_service == 0:
                    break
                else:
                    logger.log_debug(module_name, str(in_service) + ' workers still working on jobs')
                    continue

            xs = res[1][1:]
            ys = res[1][0] % options.max_classes

            predict, conf = predict_prob(xs, ys)
            corr = int(predict == ys)
            ofile.write(str(corr) + ',' + str(predict) + ',' + str(conf) + ',' + str(ys) + "\n")

        generator.stop_generator(10)

def eval_model(eval_set):
    """ Evaluate the Prob model."""
    random.shuffle(eval_set)
    temp_dir = tempfile.mkdtemp(suffix='-prob-pt')
    logger.log_info(module_name, 'Evaluation results will be written to ' + temp_dir)

    workers = list()
    for sample in eval_set:
        worker = Process(target=eval_worker_loop, args=(temp_dir, sample))
        workers.append(worker)
        worker.start()
        if len(workers) > options.threads:
            workers.pop(0).join()

    for worker in workers:
        worker.join()

if __name__ == '__main__':

    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] pt_directory bin_directory')

    parser_group_learn = OptionGroup(parser, 'Learning Options')
    parser_group_learn.add_option('--learn-ret', action='store_true', dest='learn_ret',
                                  help='Learn to predict return destinations')
    parser_group_learn.add_option('--learn-call', action='store_true', dest='learn_call',
                                  help='Learn to predict call destinations')
    parser_group_learn.add_option('--learn-icall', action='store_true', dest='learn_icall',
                                  help='Learn to predict indirect call destinations')
    parser_group_learn.add_option('--learn-jmp', action='store_true', dest='learn_jmp',
                                  help='Learn to predict jump destinations')
    parser_group_learn.add_option('--learn-ijmp', action='store_true', dest='learn_ijmp',
                                  help='Learn to predict indirect jump destinations')
    parser.add_option_group(parser_group_learn)

    parser_group_sys = OptionGroup(parser, 'System Options')
    parser_group_sys.add_option('-l', '--logging', action='store', dest='log_level', type='int', default=20,
                                help='Logging level (10: Debug, 20: Info, 30: Warning, 40: Error, 50: Critical) (default: Info)')
    parser_group_sys.add_option('-t', '--threads', action='store', dest='threads', type='int', default=cpu_count(),
                                help='Number of threads to use when parsing PT traces (default: number of CPU cores)')
    parser_group_sys.add_option('--queue-size', action='store', dest='queue_size', type='int', default=32768,
                                help='Size of the results queue, making this too large may exhaust memory (default 32768)')
    parser_group_sys.add_option('--skip-train', action='store_true', dest='skip_train',
                                help='Skip training')
    parser_group_sys.add_option('--skip-test', action='store_true', dest='skip_test',
                                help='Skip testing')
    parser_group_sys.add_option('--skip-eval', action='store_true', dest='skip_eval',
                                help='Skip evaluation')
    parser.add_option_group(parser_group_sys)

    parser_group_data = OptionGroup(parser, 'Data Options')
    parser_group_data.add_option('-p', '--preprocessed', action='store_true', dest='preprocess',
                                 help='Only use samples where a preprocessed trace is available')
    parser_group_data.add_option('--train-size', action='store', dest='train_size', type='int', default=8,
                                 help='Number of traces to train on (default: 8)')
    parser_group_data.add_option('--test-size', action='store', dest='test_size', type='int', default=2,
                                 help='Number of traces to test on (default: 2)')
    parser_group_data.add_option('-r', '--ratio', action='store', dest='sample_ratio', type='float', default=0.5,
                                 help='The ratio of benign to malicious samples to use (default: 0.5)')
    parser_group_data.add_option('-o', '--output-sets', action='store', dest='output_sets', type='string', default='',
                                 help='Write the picked samples to the provided file so these sets can be resused in future runs (see -i)')
    parser_group_data.add_option('-i', '--input-sets', action='store', dest='input_sets', type='string', default='',
                                 help='Instead of using train-size and test-size, load the samples from this file (see -o).')
    parser.add_option_group(parser_group_data)

    parser_group_prob = OptionGroup(parser, 'Prob Options')
    parser_group_prob.add_option('-s', '--sequence-len', action='store', dest='seq_len', type='int', default=32,
                                 help='Length of sequences fed into Prob (default: 32)')
    parser_group_prob.add_option('--max-classes', action='store', dest='max_classes', type='int', default=256,
                                 help='The max number of classes to use (default: 256)')
    parser.add_option_group(parser_group_prob)

    parser_group_redis = OptionGroup(parser, 'Redis Options')
    parser_group_redis.add_option('--hostname', action='store', dest='redis_host', type='string', default='localhost',
                                  help='Hostname for Redis database (default: localhost)')
    parser_group_redis.add_option('--port', action='store', dest='redis_port', type='int', default=6379,
                                  help='Port for Redis database (default: 6379)')
    parser_group_redis.add_option('--db', action='store', dest='redis_db', type='int', default=0,
                                  help='DB number for Redis database (default: 0)')
    parser.add_option_group(parser_group_redis)

    options, args = parser.parse_args()

    if len(args) < 2:
        parser.print_help()
        sys.exit(0)

    root_dir = args[0]
    bin_dirpath = args[1]

    # Initialization
    logger.log_start(options.log_level)

    # Input validation
    errors = False
    if not path.isdir(bin_dirpath):
        logger.log_error(module_Name, 'bin_directory must be a directory')
        errors = True

    if options.threads < 1:
        logger.log_error(module_name, 'Parsing requires at least 1 thread')
        errors = True

    if options.seq_len < 2:
        logger.log_error(module_name, 'Sequence length must be at least 2')
        errors = True

    if options.train_size < 1:
        logger.log_error(module_name, 'Training size must be at least 1')
        errors = True

    if options.test_size < 1:
        logger.log_error(module_name, 'Test size must be at least 1')
        errors = True

    if options.learn_ret:
        filters.add_filter('ret')

    if options.learn_call:
        filters.add_filter('call')

    if options.learn_icall:
        filters.add_filter('icall')

    if options.learn_jmp:
        filters.add_filter('jmp')

    if options.learn_ijmp:
        filters.add_filter('ijmp')

    if errors:
        clean_exit(EXIT_INVALID_ARGS, 'Failed to parse options')

    if filters.get_num_enabled() == 0:
        clean_exit(EXIT_INVALID_ARGS, 'Must set at least one learning flag in "Learning Options" section')

    # Further initialization
    if not options.preprocess:
        redis_info = [options.redis_host, options.redis_port, options.redis_db]
    else:
        redis_info = None

    init_prob(not options.skip_train)  # flush Redis DB iff there will be training

    logger.log_info(module_name, 'Scanning ' + str(root_dir))
    fs = reader.parse_pt_dir(root_dir)
    if fs is None or len(fs) == 0:
        clean_exit(EXIT_INVALID_ARGS, 'Directory ' + str(root_dir) + ' does not contain the expected file layout')

    if options.preprocess:
        fs = [x for x in fs if 'parsed_filepath' in x.keys()]

    benign = [x for x in fs if x['label'] == 'benign']
    malicious = [x for x in fs if x['label'] == 'malicious']

    logger.log_info(module_name, 'Found ' + str(len(benign)) + ' benign traces and ' + str(len(malicious)) + ' malicious traces')

    sets_meta = {'b_train': [], 'b_test': [], 'm_test': []}

    # User has the option of providing an input file that tells us which samples to use.
    if len(options.input_sets) > 0:
        load_sets()
    # Otherwise, we're going to pick randomly based on train-size and test-size.
    else:
        b_train_size = int(options.train_size)
        b_test_size = int(options.test_size * options.sample_ratio)
        m_test_size = options.test_size - b_test_size

        if len(benign) < b_train_size + b_test_size:
            clean_exit(EXIT_RUNTIME_ERROR, 'Not enough benign samples! Need ' + str(b_train_size + b_test_size) + ' have ' + str(len(benign)))

        if len(malicious) < m_test_size:
            clean_exit(EXIT_RUNTIME_ERROR, 'Not enough malicious samples! Need ' + str(m_test_size) + ' have ' + str(len(malicious)))

        random.seed() # We don't need a secure random shuffle, so this is good enough
        random.shuffle(benign)
        random.shuffle(malicious)

        if b_train_size > 0:
            sets_meta['b_train'] = benign[:b_train_size]
        if b_test_size > 0:
            sets_meta['b_test'] = benign[-b_test_size:]
        if m_test_size > 0:
            sets_meta['m_test'] = malicious[-m_test_size:]

    logger.log_info(module_name, 'Selected ' + ', '.join([str(len(sets_meta[x])) + ' ' +  str(x) for x in sets_meta.keys()]))

    if len(options.output_sets) > 0:
        save_sets()

    # Train model
    if not options.skip_train:
        logger.log_info(module_name, 'Starting training')
        try:
            train_model(sets_meta['b_train'])
        except KeyboardInterrupt:
            clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...', True)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()), True)
    else:
        logger.log_info(module_name, 'Skipping training')

    # Test model
    if not options.skip_test:
        logger.log_info(module_name, 'Starting testing')
        try:
            test_model(sets_meta['b_test'])
        except KeyboardInterrupt:
            clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...', True)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()), True)
    else:
        logger.log_info(module_name, 'Skipping testing')

    # Evaluate model
    if not options.skip_eval:
        logger.log_info(module_name, 'Starting evaluation')
        try:
            eval_model(sets_meta['b_test'] + sets_meta['m_test'])
        except KeyboardInterrupt:
            clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...', True)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()), True)
    else:
        logger.log_info(module_name, 'Skipping evaluation')

    # Cleanup
    logger.log_info(module_name, 'Cleaning up and exiting')
    logger.log_stop()
