#!/usr/bin/env python

import sys
import logger
import logging
import reader
import generator
from optparse import OptionParser, OptionGroup
import numpy as np
import random
from multiprocessing import cpu_count
from datetime import datetime

module_name = 'LSTM'

def clean_exit(error_code, message):
    """ Performs a clean exit, useful for when errors happen that can't be recovered from."""
    logger.log_critical(module_name, message)
    logger.log_stop()
    sys.exit(error_code)

def build_model():
    """ Builds the LSTM model assuming two categories."""
    model = Sequential()

    model.add(
        LSTM(
            options.units,
            input_shape=(options.seq_len, 1),
            return_sequences=False
        )
    )

    model.add(Dense(2, activation='softmax'))

    model.compile(loss='sparse_categorical_crossentropy',
                  optimizer='rmsprop',
                  metrics=['sparse_categorical_accuracy'])

    return model

def map_to_model(samples, f):
    """ A helper function because train_on_batch() and test_on_batch() are so similar."""
    random.shuffle(samples)
    # There's no point spinning up more worker threads than there are samples
    threads = min(options.threads, len(samples))

    # When you gonna fire it up? When you gonna fire it up?
    iqueue, oqueue = generator.start_generator(threads, reader.read_pt_file, options.queue_size,
                                               options.seq_len, not options.no_sw)

    for sample in samples:
        if sample['label'] == 'malicious':
            sample_label = 1
        elif sample['label'] == 'benign':
            sample_label = 0
        else:
            logger.log_warning(module_name, 'Unknown label `' + str(sample['label']) + '`, skipping')
            continue

        sample_memory = reader.read_memory_file(sample['mapping_filepath'])

        if sample_memory is None:
            logger.log_warning(module_name, 'Failed to parse memory file, skipping')
            continue

        iqueue.put((sample_label, sample['trace_filepath'], sample_memory, encoding, options.tip_only))

    # Get parsed sequences and feed them to the LSTM model
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
                logger.log_info(module_name, str(in_service) + ' workers still working on jobs')
                continue

        xs.append([list([seq]) for seq in res[1]])
        ys.append(res[0])

        if len(ys) == options.batch_size:
            yield f(np.array(xs), np.array(ys))
            xs = []
            ys = []

    generator.stop_generator(10)
    # End of generator
    while True:
        yield None

def train_model():
    """ Trains the LSTM model."""
    training_set = sets_meta['b_train'] + sets_meta['m_train']
    start_time = datetime.now()
    freq_c = options.checkpoint_interval * 60
    last_c = datetime.now()
    for status in map_to_model(training_set, model.train_on_batch):
        if status is None:
            break
        if freq_c > 0 and (datetime.now() - last_c).total_seconds() > freq_c:
            logger.log_debug(module_name, 'Checkpointing weights')
            try:
                model.save_weights(options.save_weights)
            except:
                generator.stop_generator(10)
                clean_exit(2, 'Failed to save LSTM weights')
            last_c = datetime.now()
    logger.log_debug(module_name, 'Training finished in ' + str(datetime.now() - start_time))

def test_model():
    """ Test the LSTM model."""
    res = [0.0] * len(model.metrics_names)
    batches = 0
    testing_set = sets_meta['b_test'] + sets_meta['m_test']

    for status in map_to_model(testing_set, model.test_on_batch):
        if status is None:
            break
        for stat in range(len(status)):
            res[stat] += status[stat]
        batches += 1

    if batches < 1:
        logger.log_warning(module_name, 'Testing set did not generate a full batch of data, cannot test')
        return

    for stat in range(len(res)):
        res[stat] /= batches

    logger.log_info(module_name, 'Results: ' + ', '.join([str(model.metrics_names[x]) + ' ' + str(res[x]) for x in range(len(res))]))

def eval_model():
    """ Evaluate the LSTM model."""
    samples = sets_meta['b_test'] + sets_meta['m_test']
    random.shuffle(samples)
    # There's no point spinning up more worker threads than there are samples
    threads = min(options.threads, len(samples))

    iqueue, oqueue = generator.start_generator(threads, reader.read_pt_file, options.queue_size,
                                               options.seq_len, not options.no_sw)

    for idx in range(len(samples)):
        sample = samples[idx]
        sample['guess'] = 'benign'
        sample_memory = reader.read_memory_file(sample['mapping_filepath'])

        if sample_memory is None:
            logger.log_warning(module_name, 'Failed to parse memory file, skipping')
            continue

        iqueue.put((idx, sample['trace_filepath'], sample_memory, encoding, options.tip_only))

    # Get parsed sequences and feed them to the LSTM model
    xs = []
    ss = []
    while True:
        try:
            res = oqueue.get(True, 5)
        except:
            in_service = generator.get_in_service()
            if in_service == 0:
                break
            else:
                logger.log_info(module_name, str(in_service) + ' workers still working on jobs')
                continue

        xs.append([list([seq]) for seq in res[1]])
        ss.append(res[0])

        if len(ss) == options.batch_size:
            ps = model.predict_on_batch(np.array(xs))
            for idx in range(len(ps)):
                if ps[idx][1] > options.eval_threshold:
                    samples[ss[idx]]['guess'] = 'malicious'
            xs = []
            ss = []

    generator.stop_generator(10)

    correct = 0
    wrong = 0
    for sample in samples:
        logger.log_debug(module_name, 'Guessed ' + str(sample['guess']) +  ', was ' + str(sample['label']))
        if sample['label'] == sample['guess']:
            correct += 1
        else:
            wrong += 1
    accuracy = float(correct) / float(correct + wrong)

    logger.log_info(module_name, 'Evaluation: ' + str(correct) + ' correct, ' + str(wrong) + ' wrong, ' + str(accuracy))

if __name__ == '__main__':

    # Parse input arguments
    parser = OptionParser(usage='Usage: %prog [options] directory')

    parser_group_sys = OptionGroup(parser, 'System Options')
    parser_group_sys.add_option('-l', '--logging', action='store', dest='log_level', type='int', default=20,
                                help='Logging level (10: Debug, 20: Info, 30: Warning, 40: Error, 50: Critical) (default: Info)')
    parser_group_sys.add_option('-t', '--threads', action='store', dest='threads', type='int', default=cpu_count(),
                                help='Number of threads to use when parsing PT traces (default: number of CPU cores)')
    parser_group_sys.add_option('--queue-size', action='store', dest='queue_size', type='int', default=32768,
                                help='Size of the results queue, making this too large may exhaust memory (default 32768)')
    parser_group_sys.add_option('--skip-test', action='store_true', dest='skip_test',
                                help='Skip the testing stage, useful when combined with saving to just make and store a model')
    parser_group_sys.add_option('--skip-eval', action='store_true', dest='skip_eval',
                                help='Skip the evaluation stage, useful when combined with saving to just make and store a model')
    parser_group_sys.add_option('--no-sliding-window', action='store_true', dest='no_sw',
                                help='Do not use sliding window, which will result in less sequences being generated')
    parser_group_sys.add_option('--tip-only', action='store_true', dest='tip_only',
                                help='Only generate sequences from TIP packets, which will result in less sequences being generated')
    parser.add_option_group(parser_group_sys)

    parser_group_data = OptionGroup(parser, 'Data Options')
    parser_group_data.add_option('--train-size', action='store', dest='train_size', type='int', default=32,
                                 help='Number of traces to train on (default: 32)')
    parser_group_data.add_option('--test-size', action='store', dest='test_size', type='int', default=2,
                                 help='Number of traces to test on (default: 2)')
    parser_group_data.add_option('-r', '--ratio', action='store', dest='sample_ratio', type='float', default=0.5,
                                 help='The ratio of benign to malicious samples to use (default: 0.5)')
    parser_group_data.add_option('-o', '--output-sets', action='store', dest='output_sets', type='string', default='',
                                 help='Write the picked samples to the provided file so these sets can be resused in future runs (see -i)')
    parser_group_data.add_option('-i', '--input-sets', action='store', dest='input_sets', type='string', default='',
                                 help='Instead of using train-size, test-size, and ratio, load the samples from this file (see -o).')
    parser.add_option_group(parser_group_data)

    parser_group_lstm = OptionGroup(parser, 'LSTM Options')
    parser_group_lstm.add_option('-s', '--sequence-len', action='store', dest='seq_len', type='int', default=128,
                                 help='Length of sequences fed into LSTM (default: 128)')
    parser_group_lstm.add_option('-b', '--batch-size', action='store', dest='batch_size', type='int', default=128,
                                 help='Number of sequences per batch (default: 128)')
    parser_group_lstm.add_option('-e', '--epochs', action='store', dest='epochs', type='int', default=1,
                                 help='Number of times to iterate over test sets (default: 1)')
    parser_group_lstm.add_option('--units', action='store', dest='units', type='int', default=100,
                                 help='Number of units to use in LSTM (default: 100)')
    parser_group_lstm.add_option('--save-model', action='store', dest='save_model', type='string', default='',
                                 help='Save the generated model to the provided filepath in JSON format')
    parser_group_lstm.add_option('--save-weights', action='store', dest='save_weights', type='string', default='',
                                 help='Save the weights after training to the provided filepath in H5 format')
    parser_group_lstm.add_option('--checkpoint', action='store', dest='checkpoint_interval', type='int', default=0,
                                 help='Save current weights every X minutes (default: only save after training)')
    parser_group_lstm.add_option('--use-model', action='store', dest='use_model', type='string', default='',
                                 help='Load the model from the provided filepath instead of building a new one')
    parser_group_lstm.add_option('--use-weights', action='store', dest='use_weights', type='string', default='',
                                 help='Load weights from the provided filepath (this will skip training and head straight to evaluation)')
    parser_group_lstm.add_option('--eval-threshold', action='store', dest='eval_threshold', type='float', default=0.95,
                                 help='How confident model has to be that a sequence is malicious to mark the trace malicious (default: 0.95)')
    parser.add_option_group(parser_group_lstm)

    options, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    # Keras likes to print $@!& to stdout, so don't import it until after the input parameters have been validated
    from keras.models import Sequential, model_from_json
    from keras.layers import Dense, LSTM
    from keras import callbacks as cb

    root_dir = args[0]

    # Initialization
    logger.log_start(options.log_level)

    # Input validation
    errors = False
    if options.threads < 1:
        logger.log_error(module_name, 'Parsing requires at least 1 thread')
        errors = True

    if options.sample_ratio < 0 or options.sample_ratio > 1:
        logger.log_error(module_name, 'Ratio must be between 0 and 1')
        errors = True
    elif options.sample_ratio == 0:
        logger.log_warning(module_name, 'Ratio is 0, no benign samples will be used!')
    elif options.sample_ratio == 1:
        logger.log_warning(module_name, 'Ratio is 1, no malicious samples will be used!')

    if options.seq_len < 2:
        logger.log_error(module_name, 'Sequence length must be at least 2')
        errors = True

    if options.batch_size < 1:
        logger.log_error(module_name, 'Batch size must be at least 1')
        errors = True

    if options.epochs < 1:
        logger.log_error(module_name, 'Epochs must be at least 1')
        errors = True

    if options.train_size < 1:
        logger.log_error(module_name, 'Training size must be at least 1')
        errors = True

    if options.test_size < 1:
        logger.log_error(module_name, 'Test size must be at least 1')
        errors = True

    if options.units < 1:
        logger.log_error(module_name, 'LSTM must have at least 1 unit')
        errors = True

    if options.checkpoint_interval < 0:
        logger.log_error(module_name, 'Checkpoint interval cannot be negative')
        errors = True

    if options.checkpoint_interval > 0 and len(options.save_weights) < 1:
        logger.log_error(module_name, 'Checkpointing requires --save-weights')
        errors = True

    if errors:
        clean_exit(1, 'Failed to parse options')

    # Further initialization
    logger.log_info(module_name, 'Scanning ' + str(root_dir))
    fs = reader.parse_pt_dir(root_dir)
    if fs is None or len(fs) == 0:
        clean_exit(1, 'Directory ' + str(root_dir) + ' does not contain the expected file layout')

    benign = [x for x in fs if x['label'] == 'benign']
    malicious = [x for x in fs if x['label'] == 'malicious']

    logger.log_info(module_name, 'Found ' + str(len(benign)) + ' benign traces and ' + str(len(malicious)) + ' malicious traces')

    sets_meta = {'m_train': [], 'b_train': [], 'm_test': [], 'b_test': []}

    # User has the option of providing an input file that tells us which samples to use.
    if len(options.input_sets) > 0:
        # TODO - Implement input_sets (-i)
        clean_exit(2, '-i not implemented yet!')
    # Otherwise, we're going to pick randomly based on train-size, test-size, and ratio.
    else:
        b_train_size = int(options.train_size * options.sample_ratio)
        b_test_size = int(options.test_size * options.sample_ratio)
        m_train_size = options.train_size - b_train_size
        m_test_size = options.test_size - b_test_size

        if len(benign) < b_train_size + b_test_size:
            clean_exit(3, 'Not enough benign samples! Need ' + str(b_train_size + b_test_size) + ' have ' + str(len(benign)))

        if len(malicious) < m_train_size + m_test_size:
            clean_exit(3, 'Not enough malicious samples! Need ' + str(m_train_size + m_test_size) + ' have ' + str(len(malicious)))

        random.seed() # We don't need a secure random shuffle, so this is good enough
        random.shuffle(benign)
        random.shuffle(malicious)

        if b_train_size > 0:
            sets_meta['b_train'] = benign[:b_train_size]
        if b_test_size > 0:
            sets_meta['b_test'] = benign[-b_test_size:]
        if m_train_size > 0:
            sets_meta['m_train'] = malicious[:m_train_size]
        if m_test_size > 0:
            sets_meta['m_test'] = malicious[-m_test_size:]

    logger.log_info(module_name, 'Selected ' + ', '.join([str(len(sets_meta[x])) + ' ' +  str(x) for x in sets_meta.keys()]))

    if len(options.output_sets) > 0:
        # TODO - Implement output_sets (-o)
        clean_exit(2, '-o not implemented yet!')

    # Build model if user didn't provide one
    if len(options.use_model) == 0:
        logger.log_info(module_name, 'Building LSTM model')
        try:
            model = build_model()
        except:
            clean_exit(3, 'Error while building model!')
    else:
        logger.log_info(module_name, 'Restoring LSTM model from provided filepath')
        try:
            with open(options.use_model, 'r') as ifile:
                model = model_from_json(ifile.read())
            model.compile(loss='sparse_categorical_crossentropy',
                          optimizer='rmsprop',
                          metrics=['sparse_categorical_accuracy'])
        except:
            clean_exit(3, 'Failed to load model from JSON file')

    if len(options.save_model) > 0:
        try:
            logger.log_info(module_name, 'Saving LSTM model')
            with open(options.save_model, 'w') as ofile:
                ofile.write(model.to_json())
        except:
            clean_exit(2, 'Failed to save LSTM model')

    # Every trace is of the same program (Adobe Acrobat Reader), which loads the same
    # files, therefore we can build our encoding using any sample.
    try:
        encoding = reader.encoding_from_memory(reader.read_memory_file(fs[0]['mapping_filepath']))
    except:
        clean_exit(3, 'Failed to create encoding! Tried using ' + fs[0]['mapping_filepath'])

    # Train model if user didn't already provide weights
    if len(options.use_weights) == 0:
        for epoch in range(options.epochs):
            logger.log_info(module_name, 'Starting training epoch ' + str(epoch + 1))
            train_model()
    else:
        logger.log_info(module_name, 'Restoring LSTM weights from provided filepath')
        try:
            model.load_weights(options.use_weights)
        except:
            clean_exit(3, 'Failed to load weights from file')

    if len(options.save_weights) > 0:
        try:
            model.save_weights(options.save_weights)
        except:
            clean_exit(2, 'Failed to save LSTM weights')

    # Test model
    if not options.skip_test:
        logger.log_info(module_name, 'Starting testing')
        test_model()
    else:
        logger.log_info(module_name, 'Skipping testing')

    # Evaluating model
    if not options.skip_eval:
        logger.log_info(module_name, 'Starting evaluation')
        eval_model()
    else:
        logger.log_info(module_name, 'Skipping evaluation')

    # Cleanup
    logger.log_info(module_name, 'Cleaning up and exiting')
    logger.log_stop()
