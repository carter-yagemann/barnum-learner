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
import gzip
import struct
from multiprocessing import Pool
from optparse import OptionParser, OptionGroup

import numpy as np
from sklearn.neighbors import NearestNeighbors
import redis

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
    res = [int(line.split(',', 1)[0]) for line in gzip.open(ifile).readlines()]
    bbs = [int(line[::-1].split(',', 1)[0][::-1]) for line in gzip.open(ifile).readlines()]
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
    parser = OptionParser(usage='Usage: %prog [options]')

    parser_group_train = OptionGroup(parser, 'Training Options')
    parser_group_train.add_option('-t', '--train-dir', action='store', dest='tdir', type='str', default=None,
                                  help='Train KNN using evaluation files in this directory.')
    parser_group_train.add_option('-m', '--max-val', action='store', dest='max_val', type='int', default=1024,
                                  help='This should match the --max-classes param from lstm.py and prob.py (default: 1024)')
    parser.add_option_group(parser_group_train)

    parser_group_query = OptionGroup(parser, 'Query Options')
    parser_group_query.add_option('-q', '--query-dir', action='store', dest='qdir', type='str', default=None,
                                  help='Query KNN using evaluation files in this directory.')
    parser.add_option_group(parser_group_query)

    parser_group_filter = OptionGroup(parser, 'Filter Options')
    parser_group_filter.add_option('-b', '--blacklist', action='store', dest='bl_path', type='str', default=None,
                                   help='Newline seperated list of PDF SHA256 hashes. Do not train or query these.')
    parser.add_option_group(parser_group_filter)

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
    if options.bl_path and not os.path.isfile(options.bl_path):
        sys.stderr.write(options.bl_path + " is not a file\n")
        errors = True

    if errors:
        parser.print_help()
        sys.exit(1)

    return (options, args)

def apply_blacklist(blacklist, files, values):
    for index, name in enumerate(files):
        for hash in blacklist:
            if hash in name:
                del files[index]
                del values[index]
                break
    return (files, values)

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

    knn = NearestNeighbors(metric='cosine')
    conn = None
    blacklist = None

    if options.bl_path:
        blacklist = [line.strip() for line in open(options.bl_path, 'r').readlines()]
    if options.use_redis:
        conn = redis.StrictRedis(options.redis_host, options.redis_port, options.redis_db)
    if options.tdir:
        ifiles = [os.path.join(options.tdir, file) for file in os.listdir(options.tdir)]
        ifiles = [file for file in ifiles if len(file) >= 3 and os.path.isfile(file) and file[-3:] == '.gz']
    qfiles = [os.path.join(options.qdir, file) for file in os.listdir(options.qdir)]
    qfiles = [file for file in qfiles if len(file) >= 3 and os.path.isfile(file) and file[-3:] == '.gz']

    pool = Pool()
    sys.stdout.write("Generating training inputs\n")
    if options.tdir:
        p_args = zip(ifiles, [options.max_val] * len(ifiles))
        train  = [res for res in pool.map(process_eval, p_args) if res[1]]
        ifiles = [res[0] for res in train]  # Removing files that couldn't be sliced
        train  = [res[1] for res in train]  # train is now only the one-hots
    elif conn:
        ifiles, train = load_redis(conn)
    else:  # This should never happen
        sys.stderr.write("No training directory or Redis connection, cannot continue\n")
        pool.close()
        sys.exit(1)
    sys.stdout.write("Generating query inputs\n")
    p_args = zip(qfiles, [options.max_val] * len(qfiles))
    query  = [res for res in pool.map(process_eval, p_args) if res[1]]
    qfiles = [res[0] for res in query]  # Removing files that couldn't be sliced
    query  = [res[1] for res in query]  # query is now only the one-hots
    pool.close()

    if blacklist:
        ifiles, train = apply_blacklist(blacklist, ifiles, train)
        qfiles, query = apply_blacklist(blacklist, qfiles, query)

    assert len(ifiles) == len(train)
    assert len(qfiles) == len(query)

    # Note: if only conn, no need to save because samples are already from Redis!
    if conn and options.tdir:
        sys.stdout.write("Saving processed training samples to Redis\n")
        save_redis(conn, ifiles, train)

    sys.stdout.write("Training KNN\n")
    knn.fit(train)

    for index, file in enumerate(qfiles):
        sys.stdout.write(file + "\n")
        nn = knn.kneighbors([query[index]], 1, True)
        sys.stdout.write("    " + str(nn[0][0][0]) + " " + str(ifiles[nn[1][0][0]]) + "\n")

if __name__ == '__main__':
    main()
