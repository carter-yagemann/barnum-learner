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
from os import path, mkdir
import logger
import logging
import reader
import generator
import filters
from optparse import OptionParser, OptionGroup
import numpy as np
import random
from multiprocessing import cpu_count
from datetime import datetime
import traceback
import tempfile
import gzip

module_name = 'LSTM'
module_version = '1.1.2'

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
                    if not path.abspath(root_dir) in line:
                        logger.log_warning(module_name, 'Input data specified with -i must be in ' + str(root_dir) + ', skipping')
                        continue
                    if not path.isdir(line):
                        logger.log_warning(module_name, 'Cannot find directory ' + str(line) + ' to load data from, skipping')
                        continue
                    matches = [record for record in fs if record['base_dir'] == line]
                    if len(matches) < 1:
                        logger.log_warning(module_name, 'Could not find data in directory ' + str(line) + ', skipping')
                        continue
                    sets_meta[set_key].append(matches[0])
    except:
        clean_exit(EXIT_RUNTIME_ERROR, "Failed to load sets from " + str(options.input_sets))

def build_model():
    """ Builds the LSTM model assuming two categories."""
    model = Sequential()

    model.add(Embedding(input_dim=options.embedding_in_dim,
                        output_dim=options.embedding_out_dim,
                        input_length=options.seq_len))

    model.add(LSTM(options.units, return_sequences=True))
    model.add(Activation('relu'))

    model.add(LSTM(options.units, return_sequences=True))
    model.add(Activation('relu'))

    model.add(LSTM(options.units))

    model.add(Dense(128))
    model.add(Activation('relu'))

    model.add(Dropout(options.dropout))

    model.add(Dense(options.max_classes))
    model.add(Activation('softmax'))

    if not options.multi_gpu is None:
        model = multi_gpu_model(model, gpus=options.multi_gpu)
        # Keras splits batches evenly between GPUs. For example, if batch size is 64 and you're using
        # 2 GPUs, each GPU will receive 32 samples per batch. When the user sets batch size, they
        # probably expect it to be per-GPU, so we adjust accordingly.
        options.batch_size *= options.multi_gpu

    opt = optimizers.RMSprop(lr=options.learning_rate, decay=options.learning_decay)
    model.compile(loss='sparse_categorical_crossentropy',
                  optimizer=opt,
                  metrics=['sparse_categorical_accuracy', 'sparse_top_k_categorical_accuracy'])

    logger.log_info(module_name, 'Model Summary:')
    model.summary(print_fn=(lambda x: logger.log_info(module_name, x)))

    return model

def map_to_model(samples, f):
    """ A helper function because train_on_batch() and test_on_batch() are so similar."""
    random.shuffle(samples)
    # There's no point spinning up more worker threads than there are samples
    threads = min(options.threads, len(samples))

    if options.preprocess:
        gen_func = reader.read_preprocessed
    else:
        gen_func = reader.disasm_pt_file

    # When you gonna fire it up? When you gonna fire it up?
    iqueue, oqueue = generator.start_generator(threads, gen_func, options.queue_size, options.seq_len)

    for sample in samples:
        if options.preprocess:
            iqueue.put((None, sample['parsed_filepath']))
        else:
            sample_memory = reader.read_memory_file(sample['mapping_filepath'])
            if sample_memory is None:
                logger.log_warning(module_name, 'Failed to parse memory file, skipping')
                continue
            iqueue.put((None, sample['trace_filepath'], options.bin_dir, sample_memory, options.timeout))

    # Get parsed sequences and feed them to the LSTM model
    batch_cnt = 0
    xs = []
    ys = []
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

        xs.append([x % options.embedding_in_dim for x in res[1][1:]])
        ys.append(res[1][0] % options.max_classes)

        if len(ys) == options.batch_size:
            yield f(np.array(xs), np.array(ys))
            xs = []
            ys = []
            batch_cnt += 1

    logger.log_info(module_name, "Processed " + str(batch_cnt) + " batches, " + str(batch_cnt * options.batch_size) + " samples")

    generator.stop_generator(10)
    # End of generator
    while True:
        yield None

def train_model(training_set):
    """ Trains the LSTM model."""
    start_time = datetime.now()
    # Checkpointing for saving model weights
    freq_c = options.checkpoint_interval * 60
    last_c = datetime.now()
    last_b = 10000
    # For reporting current metrics
    freq_s = options.status_interval * 60
    last_s = datetime.now()

    res = [0.0] * len(model.metrics_names)
    batches = 0
    num_samples = len(training_set)
    for status in map_to_model(training_set, model.train_on_batch):
        if status is None:
            break
        for stat in range(len(status)):
            res[stat] += status[stat]
        batches += 1
        # Print current metrics every minute
        if (datetime.now() - last_s).total_seconds() > freq_s:
            c_metrics = [status / batches for status in res]
            c_metrics_str = ', '.join([str(model.metrics_names[x]) + ' ' + '%.12f' % (c_metrics[x]) for x in range(len(c_metrics))])
            c_metrics_str += ', progress %.4f' % (float(generator.fin_tasks.value) / float(num_samples))
            logger.log_info(module_name, 'Status: ' + c_metrics_str)
            last_s = datetime.now()
        # Save current weights at user specified frequency
        if freq_c > 0 and (datetime.now() - last_c).total_seconds() > freq_c:
            logger.log_debug(module_name, 'Checkpointing weights')
            c_metrics = [status / batches for status in res]
            if not options.checkpoint_best or c_metrics[0] < last_b:
                try:
                    model.save_weights(options.save_weights)
                except:
                    generator.stop_generator(10)
                    clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM weights:\n" + str(traceback.format_exc()))
            if options.checkpoint_es and c_metrics[0] > last_b:
                logger.log_info(module_name, 'Loss did not improve between checkpoints, early stopping and restoring last weights')
                generator.stop_generator(10)
                try:
                    model.load_weights(options.save_weights)
                except:
                    clean_exit(EXIT_RUNTIME_ERROR, "Failed to load LSTM weights:\n" + str(traceback.format_exc()))
                return
            last_b = c_metrics[0]
            last_c = datetime.now()

    if batches < 1:
        logger.log_warning(module_name, 'Testing set did not generate a full batch of data, cannot test')
        return

    for stat in range(len(res)):
        res[stat] /= batches

    logger.log_info(module_name, 'Results: ' + ', '.join([str(model.metrics_names[x]) + ' ' + str(res[x]) for x in range(len(res))]))
    logger.log_debug(module_name, 'Training finished in ' + str(datetime.now() - start_time))

    return res[0] # Average Loss

def test_model(testing_set):
    """ Test the LSTM model."""
    # For reporting current metrics
    freq_s = options.status_interval * 60
    last_s = datetime.now()

    res = [0.0] * len(model.metrics_names)
    batches = 0
    num_samples = len(testing_set)

    for status in map_to_model(testing_set, model.test_on_batch):
        if status is None:
            break
        for stat in range(len(status)):
            res[stat] += status[stat]
        batches += 1
        # Print current metrics every minute
        if (datetime.now() - last_s).total_seconds() > freq_s:
            c_metrics = [status / batches for status in res]
            c_metrics_str = ', '.join([str(model.metrics_names[x]) + ' ' + '%.12f' % (c_metrics[x]) for x in range(len(c_metrics))])
            c_metrics_str += ', progress %.4f' % (float(generator.fin_tasks.value) / float(num_samples))
            logger.log_info(module_name, 'Status: ' + c_metrics_str)
            last_s = datetime.now()

    if batches < 1:
        logger.log_warning(module_name, 'Testing set did not generate a full batch of data, cannot test')
        return

    for stat in range(len(res)):
        res[stat] /= batches

    logger.log_info(module_name, 'Results: ' + ', '.join([str(model.metrics_names[x]) + ' ' + str(res[x]) for x in range(len(res))]))

def eval_model(eval_set):
    """ Evaluate the LSTM model."""
    random.shuffle(eval_set)
    if options.eval_dir is None:
        eval_dir = tempfile.mkdtemp(suffix='-lstm-pt')
    else:
        if not path.exists(options.eval_dir):
            mkdir(options.eval_dir)
        eval_dir = options.eval_dir
    logger.log_info(module_name, 'Evaluation results will be written to ' + eval_dir)

    for sample in eval_set:
        o_filename = sample['label'] + '-' + path.basename(sample['base_dir']) + '.gz'
        o_filepath = path.join(eval_dir, o_filename)
        logger.log_debug(module_name, 'Writing to ' + o_filepath)
        with gzip.open(o_filepath, 'w') as ofile:
            if options.preprocess:
                gen_func = reader.read_preprocessed
            else:
                gen_func = reader.disasm_pt_file

            iqueue, oqueue = generator.start_generator(1, gen_func, options.queue_size, options.seq_len)

            if options.preprocess:
                iqueue.put((None, sample['parsed_filepath']))
            else:
                sample_memory = reader.read_memory_file(sample['mapping_filepath'])
                if sample_memory is None:
                    logger.log_warning(module_name, 'Failed to parse memory file, skipping')
                    continue
                iqueue.put((None, sample['trace_filepath'], options.bin_dir, sample_memory, options.timeout))

            xs = []
            ys = []
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

                xs.append([x % options.embedding_in_dim for x in res[1][1:]])
                ys.append(res[1][0] % options.max_classes)

                if len(ys) == options.batch_size:
                    ps = model.predict_on_batch(np.array(xs)).tolist()
                    cs = [max(p) for p in ps]                   # Max confidence
                    ms = [p.index(max(p)) for p in ps]          # Most likely label
                    ts = [int(a == b) for a, b in zip(ms, ys)]  # Compare prediction to real label
                    for c, m, t, y in zip(cs, ms, ts, ys):
                        ofile.write(str(t) + ',' + str(m) + ',' + str(c) + ',' + str(y) + "\n")

                    xs = []
                    ys = []

            generator.stop_generator(10)

if __name__ == '__main__':

    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] pt_directory', version='Barnum LSTM ' + module_version)

    parser_group_learn = OptionGroup(parser, 'Learning Options')
    parser_group_learn.add_option('--disable-ret', action='store_false', dest='learn_ret', default=True,
                                  help='Disable learning to predict return destinations (Default: Enabled)')
    parser_group_learn.add_option('--disable-icall', action='store_false', dest='learn_icall', default=True,
                                  help='Disable learning to predict indirect call destinations (Default: Enabled)')
    parser_group_learn.add_option('--disable-ijmp', action='store_false', dest='learn_ijmp', default=True,
                                  help='Disable learning to predict indirect jump destinations (Default: Enabled)')
    parser_group_learn.add_option('--learn-call', action='store_true', dest='learn_call', default=False,
                                  help='Learn to predict call destinations (Default: Disabled)')
    parser_group_learn.add_option('--learn-jmp', action='store_true', dest='learn_jmp', default=False,
                                  help='Learn to predict jump destinations (Default: Disabled)')
    parser.add_option_group(parser_group_learn)

    parser_group_sys = OptionGroup(parser, 'System Options')
    parser_group_sys.add_option('-l', '--logging', action='store', dest='log_level', type='int', default=20,
                                help='Logging level (10: Debug, 20: Info, 30: Warning, 40: Error, 50: Critical) (default: Info)')
    parser_group_sys.add_option('--status-interval', action='store', dest='status_interval', type='int', default=60,
                                help='How frequently (in minutes) to print the current status of training or testing (default: 60)')
    parser_group_sys.add_option('-t', '--threads', action='store', dest='threads', type='int', default=cpu_count(),
                                help='Number of threads to use when parsing PT traces (default: number of CPU cores)')
    parser_group_sys.add_option('--queue-size', action='store', dest='queue_size', type='int', default=32768,
                                help='Size of the results queue, making this too large may exhaust memory (default: 32768)')
    parser_group_sys.add_option('--skip-test', action='store_true', dest='skip_test',
                                help='Skip the generalization testing stage, useful when combined with saving to just make and store a model')
    parser_group_sys.add_option('--skip-eval', action='store_true', dest='skip_eval',
                                help='Skip the evaluation stage, useful when combined with saving to just make and store a model')
    parser_group_sys.add_option('--eval-dir', action='store', type='str', default=None,
                                help='Directory to save evaluation results. If directory does not exist, it is created (default: new temp dir)')
    parser.add_option_group(parser_group_sys)

    parser_group_data = OptionGroup(parser, 'Data Options')
    parser_group_data.add_option('-p', '--preprocessed', action='store_true', dest='preprocess',
                                 help='Only use samples where a preprocessed trace is available')
    parser_group_data.add_option('--bin-dir', action='store', type='str', default=None,
                                 help='Path to directory of extracted binaries. Only needed if not using (-p).')
    parser_group_data.add_option('--train-size', action='store', dest='train_size', type='int', default=8,
                                 help='Number of traces to train on (default: 8)')
    parser_group_data.add_option('--test-size-benign', action='store', dest='test_size_b', type='int', default=2,
                                 help='Number of benign traces to test on (default: 2)')
    parser_group_data.add_option('--test-size-malicious', action='store', dest='test_size_m', type='int', default=2,
                                 help='Number of malicious traces to test on (default: 2)')
    parser_group_data.add_option('-o', '--output-sets', action='store', dest='output_sets', type='string', default='',
                                 help='Write the picked samples to the provided file so these sets can be resused in future runs (see -i)')
    parser_group_data.add_option('-i', '--input-sets', action='store', dest='input_sets', type='string', default='',
                                 help='Instead of using train-size, test-size, and ratio, load the samples from this file (see -o).')
    parser_group_data.add_option('--timeout', action='store', type='int', default=None,
                                 help='If preprocessed (-p) not set, max seconds to spend disassembling one trace (default: infinite)')
    parser.add_option_group(parser_group_data)

    parser_group_lstm = OptionGroup(parser, 'LSTM Options')
    parser_group_lstm.add_option('-s', '--sequence-len', action='store', dest='seq_len', type='int', default=32,
                                 help='Length of sequences fed into LSTM (default: 32)')
    parser_group_lstm.add_option('-b', '--batch-size', action='store', dest='batch_size', type='int', default=1536,
                                 help='Number of sequences per batch (default: 1536)')
    parser_group_lstm.add_option('-e', '--epochs', action='store', dest='epochs', type='int', default=16,
                                 help='Number of times to iterate over test sets (default: 16)')
    parser_group_lstm.add_option('--units', action='store', dest='units', type='int', default=128,
                                 help='Number of units to use in LSTM (default: 128)')
    parser_group_lstm.add_option('--max-classes', action='store', dest='max_classes', type='int', default=1024,
                                 help='The max number of classes to use (default: 1024)')
    parser_group_lstm.add_option('--embedding-input-dimension', action='store', dest='embedding_in_dim', type='int', default=200000,
                                 help='The input dimension of the embedding layer (default: 200000)')
    parser_group_lstm.add_option('--embedding-output-dimension', action='store', dest='embedding_out_dim', type='int', default=1024,
                                 help='The output dimension of the embedding layer (default: 1024)')
    parser_group_lstm.add_option('--dropout', action='store', dest='dropout', type='float', default=0.5,
                                 help='The dropout rate in the dense layer (default: 0.5)')
    parser_group_lstm.add_option('--learning-rate', action='store', dest='learning_rate', type='float', default=0.001,
                                 help='Learning rate for the RMSprop optimizer (default: 0.001)')
    parser_group_lstm.add_option('--learning-decay', action='store', dest='learning_decay', type='float', default=0.0,
                                 help='Decay rate of optimizer (default: 0.0)')
    parser_group_lstm.add_option('--save-model', action='store', dest='save_model', type='string', default='',
                                 help='Save the generated model to the provided filepath in JSON format')
    parser_group_lstm.add_option('--save-weights', action='store', dest='save_weights', type='string', default='',
                                 help='Save the weights after training to the provided filepath in H5 format')
    parser_group_lstm.add_option('--checkpoint', action='store', dest='checkpoint_interval', type='int', default=0,
                                 help='Save current weights every X minutes (default: only save after training)')
    parser_group_lstm.add_option('--checkpoint-best', action='store_true', dest='checkpoint_best',
                                 help='At checkpoint, only save weights if loss improved.')
    parser_group_lstm.add_option('--checkpoint-early-stop', action='store_true', dest='checkpoint_es',
                                 help='If loss does not improve between checkpoints, stop and restore previous weights.')
    parser_group_lstm.add_option('--use-model', action='store', dest='use_model', type='string', default='',
                                 help='Load the model from the provided filepath instead of building a new one')
    parser_group_lstm.add_option('--use-weights', action='store', dest='use_weights', type='string', default='',
                                 help='Load weights from the provided filepath (this will skip training and head straight to evaluation)')
    parser_group_lstm.add_option('--multi-gpu', action='store', type='int', default=None,
                                 help='Enable multi-GPU mode using the provided number of GPUs (default: disabled)')
    parser.add_option_group(parser_group_lstm)

    options, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    # Keras likes to print $@!& to stdout, so don't import it until after the input parameters have been validated
    from keras.models import Model, Sequential, model_from_json
    from keras.layers import Dense, LSTM, Embedding, Activation, Dropout
    from keras.utils import multi_gpu_model
    from keras import optimizers

    root_dir = args[0]

    # Initialization
    logger.log_start(options.log_level)
    logger.log_info(module_name, "Barnum LSTM " + module_version)

    # Input validation
    errors = False
    if options.threads < 1:
        logger.log_error(module_name, 'Parsing requires at least 1 thread')
        errors = True

    if options.seq_len < 2:
        logger.log_error(module_name, 'Sequence length must be at least 2')
        errors = True

    if options.batch_size < 1:
        logger.log_error(module_name, 'Batch size must be at least 1')
        errors = True

    if options.epochs < 1:
        logger.log_error(module_name, 'Epochs must be at least 1')
        errors = True

    if options.use_model == '' and options.train_size < 1:
        logger.log_error(module_name, 'Training size must be at least 1')
        errors = True

    if options.units < 1:
        logger.log_error(module_name, 'LSTM must have at least 1 unit')
        errors = True

    if options.embedding_in_dim < 1:
        logger.log_error(module_name, 'Embedding input dimension must be at least 1')
        errors = True

    if options.embedding_out_dim < 1:
        logger.log_error(module_name, 'Embedding output dimension must be at least 1')
        errors = True

    if options.dropout < 0 or options.dropout >= 1:
        logger.log_error(module_name, 'Dropout rate must be in range [0, 1)')
        errors = True

    if options.checkpoint_interval < 0:
        logger.log_error(module_name, 'Checkpoint interval cannot be negative')
        errors = True

    if options.checkpoint_interval > 0 and len(options.save_weights) < 1:
        logger.log_error(module_name, 'Checkpointing requires --save-weights')
        errors = True

    if not options.eval_dir is None and path.isfile(options.eval_dir):
        logger.log_error(module_name, 'Evaluation directory is a file, must be a directory')
        errors = True

    if not options.multi_gpu is None and options.multi_gpu < 2:
        logger.log_error(module_name, 'Value for multi-GPU mode option must be at least 2')
        errors = True

    if not options.preprocess and options.bin_dir is None:
        logger.log_error(module_name, 'Preprocessing (-p) is not set, so (--bin-dir) is required')
        errors = True

    if not options.bin_dir is None and not path.isdir(options.bin_dir):
        logger.log_error(module_name, 'Binary directory (--bin-dir) must be a directory')
        errors = True

    if options.checkpoint_interval == 0 and (options.checkpoint_best or options.checkpoint_es):
        logger.log_warning(module_name, 'Setting --checkpoint-best or --checkpoint-early-stop without --checkpoint does nothing')

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

    logger.log_info(module_name, 'Scanning ' + str(root_dir))
    fs = reader.parse_pt_dir(root_dir)
    if fs is None or len(fs) == 0:
        clean_exit(EXIT_INVALID_ARGS, 'Directory ' + str(root_dir) + ' does not contain the expected file layout')

    if options.preprocess:
        fs = [x for x in fs if 'parsed_filepath' in x.keys()]

    benign = [x for x in fs if x['label'] == 'benign']
    malicious = [x for x in fs if x['label'] == 'malicious']

    logger.log_info(module_name, 'Found ' + str(len(benign)) + ' benign traces and ' + str(len(malicious)) + ' malicious traces')

    sets_meta = {'b_train': [], 'm_test': [], 'b_test': []}

    # User has the option of providing an input file that tells us which samples to use.
    if len(options.input_sets) > 0:
        load_sets()
    # Otherwise, we're going to pick randomly based on train-size, test-size, and ratio.
    else:
        b_train_size = int(options.train_size)
        b_test_size = int(options.test_size_b)
        m_test_size = int(options.test_size_m)

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

    # Build model if user didn't provide one
    if len(options.use_model) == 0:
        logger.log_info(module_name, 'Building LSTM model')
        try:
            model = build_model()
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Error while building model:\n" + str(traceback.format_exc()))
    else:
        logger.log_info(module_name, 'Restoring LSTM model from provided filepath')
        try:
            with open(options.use_model, 'r') as ifile:
                model = model_from_json(ifile.read())
            model.compile(loss='sparse_categorical_crossentropy',
                          optimizer='rmsprop',
                          metrics=['sparse_categorical_accuracy'])
        except:
            clean_exit(EXIT_RUNTIME_ERROR, 'Failed to load model from JSON file')

    if len(options.save_model) > 0:
        try:
            logger.log_info(module_name, 'Saving LSTM model')
            with open(options.save_model, 'w') as ofile:
                ofile.write(model.to_json())
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM model:\n" + str(traceback.format_exc()))

    # Train model if user didn't already provide weights
    if len(options.use_weights) == 0:
        for epoch in range(options.epochs):
            logger.log_info(module_name, 'Starting training epoch ' + str(epoch + 1))
            try:
                curr_loss = train_model(sets_meta['b_train'])
            except KeyboardInterrupt:
                clean_exit(EXIT_USER_INTERRUPT, 'Keyboard interrupt, cleaning up...', True)
            except:
                clean_exit(EXIT_RUNTIME_ERROR, "Unexpected error:\n" + str(traceback.format_exc()), True)
            if curr_loss is None:  # Training early stopped mid-epoch
                break
    else:
        logger.log_info(module_name, 'Restoring LSTM weights from provided filepath')
        try:
            model.load_weights(options.use_weights)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, 'Failed to load weights from file')

    if len(options.save_weights) > 0:
        try:
            model.save_weights(options.save_weights)
        except:
            clean_exit(EXIT_RUNTIME_ERROR, "Failed to save LSTM weights:\n" + str(traceback.format_exc()))

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

    # Evaluating model
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
