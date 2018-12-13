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
import logging
import logger
import gzip
import struct
from multiprocessing import Pool, cpu_count
from optparse import OptionParser, OptionGroup

import numpy as np
from sklearn.neighbors import NearestNeighbors
import redis

module_name = 'Cluster'
module_version = '1.0.1'

# Error Codes
ERROR_INVALID_ARG = 1
ERROR_RUNTIME     = 2

def moving_average(a, n):
    """ Moving average of a with window size n."""
    ret = np.cumsum(a, dtype=float)
    ret[n:] = ret[n:] - ret[:-n]
    return ret[n - 1:] / n

def slice(array, window=10000, threshold=0.1):
    """ Slices array from the first index where the moving average falls belong the threshold to the last.

    Resulting slice is a slight over-approximation. If the moving average never falls below the threshold,
    the original array is returned.

    array - the array to slice.
    window - the size of the window for moving average.
    threshold - the threshold below which a slice will be taken.
    """
    avg = moving_average(array, window)
    start = np.argmax(avg < threshold)
    end = len(array) - np.argmax(avg[::-1] < threshold) + window
    return (start, end)

def process_eval(args):
    ifile, max_bbid = args
    # For each prediction, 1 if correct, 0 if wrong
    res = [int(line.split(',', 1)[0]) for line in gzip.open(ifile, 'rt').readlines()]
    bbs = [int(line[::-1].split(',', 1)[0][::-1]) for line in gzip.open(ifile, 'rt').readlines()]
    start, end = slice(res)
    if len(res[start:end]) == len(res):
        return (ifile, None)  # Could not take slice at given threshold
    one_hot = [0] * max_bbid
    for bb in bbs[start:end]:
        if bb >= max_bbid:
            continue  # Avoid out of bounds write
        one_hot[bb] = 1
    return (ifile, one_hot)

def parse_args():
    parser = OptionParser(usage='Usage: %prog [options]', version='Barnum Cluster ' + module_version)

    parser_group_sys = OptionGroup(parser, 'System Options')
    parser_group_sys.add_option('-w', '--workers', action='store', type='int', default=cpu_count(),
                                help='Max number of worker threads to use (default: number of cores)')
    parser.add_option_group(parser_group_sys)

    parser_group_train = OptionGroup(parser, 'Training Options')
    parser_group_train.add_option('-t', '--train-dir', action='store', dest='tdir', type='str', default=None,
                                  help='Train clustering using evaluation files in this directory.')
    parser_group_train.add_option('-m', '--max-val', action='store', dest='max_val', type='int', default=1024,
                                  help='This should match the --max-classes param from lstm.py and prob.py (default: 1024)')
    parser.add_option_group(parser_group_train)

    parser_group_query = OptionGroup(parser, 'Query Options')
    parser_group_query.add_option('-q', '--query-dir', action='store', dest='qdir', type='str', default=None,
                                  help='Query clustering using evaluation files in this directory.')
    parser_group_query.add_option('-c', '--csv', action='store', type='str', default=None,
                                  help='Write output as CSV to given filepath (default: no CSV)')
    parser.add_option_group(parser_group_query)

    parser_group_redis = OptionGroup(parser, 'Redis Options')
    parser_group_redis.add_option('-r', '--use-redis', action='store_true', dest='use_redis', default=False,
                                  help='Store processed training samples in Redis. Omit training dir to train from these.')
    parser_group_redis.add_option('--hostname', action='store', dest='redis_host', type='string', default='localhost',
                                  help='Hostname for Redis database (default: localhost)')
    parser_group_redis.add_option('-p', '--port', action='store', dest='redis_port', type='int', default=6379,
                                  help='Port for Redis database (default: 6379)')
    parser_group_redis.add_option('-d', '--db', action='store', dest='redis_db', type='int', default=0,
                                  help='DB number for Redis database (default: 0)')
    parser.add_option_group(parser_group_redis)

    options, args = parser.parse_args()

    # Input validation
    errors = False
    if not options.tdir and not options.use_redis:
        sys.stderr.write("Must specify either a training directory or a Redis database of already processed training samples\n")
        errors = True
    if not options.qdir:
        sys.stderr.write("Must specify a query directory to read queries from\n")
        errors = True
    if options.tdir and not os.path.isdir(options.tdir):
        sys.stderr.write(options.tdir + " is not a directory\n")
        errors = True
    if options.qdir and not os.path.isdir(options.qdir):
        sys.stderr.write(options.qdir + " is not a directory\n")
        errors = True

    if errors:
        parser.print_help()
        sys.exit(ERROR_INVALID_ARG)

    return (options, args)

def to_redis(one_hot):
    """ Pack one hot array so it can be stored in Redis. """
    return struct.pack('B' * len(one_hot), *one_hot)

def from_redis(packed_hot):
    """ Restore one hot array from Redis representation. """
    return list(struct.unpack('B' * len(packed_hot), packed_hot))

def load_redis(conn):
    ifiles = conn.keys('*')
    pipe = conn.pipeline()
    map(pipe.get, ifiles)
    one_hots = [from_redis(hot) for hot in pipe.execute()]
    return (ifiles, one_hots)

def save_redis(conn, ifiles, one_hots):
    pipe = conn.pipeline()
    for hot, ifile in zip(one_hots, ifiles):
        pipe.set(ifile, to_redis(hot))
    pipe.execute()

def main():
    options, args = parse_args()

    logger.log_start(20)
    logger.log_info(module_name, 'Barnum Cluster ' + module_version)

    knn = NearestNeighbors(metric='cosine')
    conn = None

    if options.use_redis:
        conn = redis.StrictRedis(options.redis_host, options.redis_port, options.redis_db)
    if options.tdir:
        ifiles = [os.path.join(options.tdir, file) for file in os.listdir(options.tdir)]
        ifiles = [file for file in ifiles if len(file) >= 3 and os.path.isfile(file) and file[-3:] == '.gz']
    qfiles = [os.path.join(options.qdir, file) for file in os.listdir(options.qdir)]
    qfiles = [file for file in qfiles if len(file) >= 3 and os.path.isfile(file) and file[-3:] == '.gz']

    pool = Pool(options.workers)
    logger.log_info(module_name, "Generating training inputs")
    if options.tdir:
        p_args = zip(ifiles, [options.max_val] * len(ifiles))
        train  = [res for res in pool.map(process_eval, p_args) if res[1]]
        ifiles = [res[0] for res in train]  # Removing files that couldn't be sliced
        train  = [res[1] for res in train]  # train is now only the one-hots
    elif conn:
        ifiles, train = load_redis(conn)
    else:  # This should never happen
        logger.log_error(module_name, "No training directory or Redis connection, cannot continue")
        pool.close()
        logger.log_stop()
        sys.exit(ERROR_RUNTIME)
    logger.log_info(module_name, "Generating query inputs")
    p_args = zip(qfiles, [options.max_val] * len(qfiles))
    query  = [res for res in pool.map(process_eval, p_args) if res[1]]
    qfiles = [res[0] for res in query]  # Removing files that couldn't be sliced
    query  = [res[1] for res in query]  # query is now only the one-hots
    pool.close()

    assert len(ifiles) == len(train)
    assert len(qfiles) == len(query)

    # Note: if only conn, no need to save because samples are already from Redis!
    if conn and options.tdir:
        logger.log_info(module_name, "Saving processed training samples to Redis")
        save_redis(conn, ifiles, train)

    logger.log_info(module_name, "Training clustering")
    knn.fit(train)

    if not options.csv is None:
        csv_file = open(options.csv, 'w')
        csv_file.write("query,nearest,distance\n")

    for index, file in enumerate(qfiles):
        logger.log_info(module_name, file)
        nn = knn.kneighbors([query[index]], 1, True)
        logger.log_info(module_name, "    " + str(nn[0][0][0]) + " " + str(ifiles[nn[1][0][0]]))
        if not options.csv is None:
            csv_file.write(os.path.basename(file) + ',' + os.path.basename(str(ifiles[nn[1][0][0]])) + ',' + str(nn[0][0][0]) + "\n")

    logger.log_stop()

if __name__ == '__main__':
    main()
