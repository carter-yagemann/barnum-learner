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
import logger
import logging
from optparse import OptionParser
import gzip
import pickle
import warnings
from multiprocessing import Pool, cpu_count
from hashlib import sha256
import numpy as np
from sklearn.svm import SVC
from sklearn.externals import joblib
from sklearn.metrics import roc_curve
import matplotlib
matplotlib.use('Agg')  # Hack so X isn't required
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN

module_name = 'Classifier'
module_version = '1.3.1'

# Error Codes
ERROR_INVALID_ARG = 1
ERROR_RUNTIME     = 2

CACHE_DIR = os.path.expanduser('~/.cache/barnum')

def init_cache():
    if not os.path.isdir(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR)
        except Exception as ex:
            logger.log_warning(module_name, "Failed to create cache directory: " + str(ex))

def add_cache(hash, acc, con):
    if not os.path.isdir(CACHE_DIR):
        logger.log_warning(module_name, "Cache directory does not exist, cannot update it")
        return

    ofp = os.path.join(CACHE_DIR, hash)
    data = (acc, con)
    if not os.path.exists(ofp):
        with open(ofp, 'wb') as ofile:
            pickle.dump(data, ofile)

def is_cached(hash):
    ofp = os.path.join(CACHE_DIR, hash)
    if os.path.isfile(ofp):
        return True
    return False

def get_cache(hash):
    if not is_cached(hash):
        return None

    ofp = os.path.join(CACHE_DIR, hash)
    with open(ofp, 'rb') as ifile:
        try:
            return pickle.load(ifile)
        except Exception as ex:
            logger.log_warning(module_name, "Failed to access cache: " + str(ex))
            return None

def make_roc(filepath, data, classifier):
    ys = np.array([sample[0] for sample in data])
    xs = np.array([sample[1:3] for sample in data])
    ys_score = classifier.decision_function(xs)

    fpr, tpr, _ = roc_curve(ys, ys_score)

    with open(filepath, 'w') as ofile:
        ofile.write("fp,tp\n")  # CSV header
        for fp, tp in zip(fpr, tpr):
            ofile.write(','.join([str(fp), str(tp)]) + "\n")

def parse_file(args):
    """Parse a single evaluation file"""
    ifilepath, options = args
    name = os.path.basename(ifilepath)

    if 'malicious' in name:
        label = 1
    elif 'benign' in name:
        label = 0
    else:
        return (3, 0, 0, name)

    # Check cache
    if not options.ignore_cache:
        with open(ifilepath, 'rb') as ifile:
            hash = sha256(ifile.read()).hexdigest()
        cache = get_cache(hash)
        if not cache is None:
            return (label, cache[0], cache[1], name)

    accuracy = 0
    confidence = 0.0
    cnt_acc = 0
    cnt_con = 0
    with gzip.open(ifilepath, 'rt') as ifile:
        try:
            for line in ifile:
                parts = line.strip().split(',')
                accuracy += int(parts[0])
                cnt_acc += 1
                if parts[0] == '0':
                    confidence += float(parts[2])
                    cnt_con += 1
        except (IOError, EOFError):
            logger.log_error(module_name, 'WARNING: Failed to parse ' + ifilepath)
            return (3, 0, 0, name)

    if cnt_acc == 0 or cnt_con == 0:
        return (3, 0, 0, name)

    avg_accuracy = 1.0 - float(cnt_acc) / float(accuracy)
    avg_confidence = float(cnt_con) / float(confidence)

    # Update cache
    if not options.ignore_cache:
        add_cache(hash, avg_accuracy, avg_confidence)

    return (label, avg_accuracy, avg_confidence, name)

def main():
    """Main"""
    global threshold

    parser = OptionParser(usage='Usage: %prog [options] eval_dir', version='Barnum Classifier ' + module_version)
    parser.add_option('-f', '--force', action='store_true',
                      help='Force threshold to produce no false positives (benign classified as malicious)')
    parser.add_option('-s', '--save', action='store', type='str', default=None,
                      help='Save classifier to given filepath (default: no saving)')
    parser.add_option('-l', '--load', action='store', type='str', default=None,
                      help='Use a previously saved classifier instead of making a new one')
    parser.add_option('-c', '--csv', action='store', type='str', default=None,
                      help='Save CSV of results to given filepath (default: no CSV)')
    parser.add_option('-p', '--plot', action='store', type='str', default=None,
                      help='Save plot as a PNG image to the given filepath (default: no plotting)')
    parser.add_option('-r', '--roc', action='store', type='str', default=None,
                      help='Save CSV plotting ROC curve to filepath (default: not saved)')
    parser.add_option('-w', '--workers', action='store', dest='workers', type='int', default=cpu_count(),
                      help='Number of workers to use (default: number of cores)')
    parser.add_option('-i', '--ignore-cache', action='store_true',
                      help='Do not use caching')

    options, args = parser.parse_args()

    if len(args) != 1 or options.workers < 1:
        parser.print_help()
        sys.exit(ERROR_INVALID_ARG)

    logger.log_start(20)
    logger.log_info(module_name, 'Barnum Classifier ' + module_version)

    idirpath = args[0]

    if not os.path.isdir(idirpath):
        logger.log_error(module_name, 'ERROR: ' + idirpath + " is not a directory")
        logger.log_stop()
        sys.exit(ERROR_INVALID_ARG)

    files = [os.path.join(idirpath, f) for f in os.listdir(idirpath) if os.path.isfile(os.path.join(idirpath, f))]
    num_benign = len([fp for fp in files if 'benign' in os.path.basename(fp)])
    num_malicious = len([fp for fp in files if 'malicious' in os.path.basename(fp)])

    if options.load is None and (num_benign == 0 or num_malicious == 0):
        logger.log_error(module_name, "Need at least 1 malicious and 1 benign sample to train a classifier")
        logger.log_stop()
        sys.exit(ERROR_INVALID_ARG)

    if not options.roc is None and (num_benign == 0 or num_malicious == 0):
        logger.log_error(module_name, "Need at least 1 malicious and 1 benign sample to plot a ROC curve")
        logger.log_stop()
        sys.exit(ERROR_INVALID_ARG)

    if not options.ignore_cache:
        init_cache()

    # Calculate average accuracy and confidence for each sample
    logger.log_info(module_name, "Parsing " + idirpath)
    pool = Pool(options.workers)
    data = [sample for sample in pool.map(parse_file, zip(files, [options] * len(files))) if sample[0] < 2]
    pool.close()
    ys = np.array([sample[0] for sample in data])
    xs = np.array([sample[1:3] for sample in data])

    if options.load is None:
        logger.log_info(module_name, "Creating classifier")
        # Train a new classifier from scratch
        if options.force:
            # Use ADASYN to over sample the benign class until FP falls to 0
            warnings.filterwarnings("ignore", module="imblearn")
            fp = 1.0
            ben_cnt = len([y for y in ys if y == 0])
            mal_cnt = len(ys) - ben_cnt
            ben_step = max(1, int(ben_cnt * 0.1))

            while fp > 0.0:
                ben_cnt += ben_step
                try:
                    xs_os, ys_os = ADASYN({0: ben_cnt, 1: mal_cnt}, n_jobs=options.workers).fit_resample(xs, ys)
                except ValueError:
                    continue  # Happens if change in counts produces too little change in ratio

                svm = SVC(kernel='linear')
                svm.fit(xs_os, ys_os)

                results = [[sample, svm.predict([sample[1:3]])] for sample in data]
                benign = [sample for sample in results if sample[0][0] == 0]
                fps = [sample for sample in results if sample[0][0] == 0 and sample[1] == 1]
                fp = float(len(fps)) / float(len(benign))
        else:
            svm = SVC(kernel='linear')
            svm.fit(xs, ys)
    else:
        # Use a previously saved classifier
        logger.log_info(module_name, "Loading classifier from " + options.load)
        try:
            svm = joblib.load(options.load)
            nu = None
        except Exception as ex:
            logger.log_error(module_name, "Failed to load classifier: " + str(ex))
            logger.log_stop()
            sys.exit(ERROR_RUNTIME)

    # Metrics
    results = [[sample, svm.predict([sample[1:3]])] for sample in data]
    benign = [sample for sample in results if sample[0][0] == 0]
    malicious = [sample for sample in results if sample[0][0] == 1]
    fps = [sample for sample in results if sample[0][0] == 0 and sample[1] == 1]
    fns = [sample for sample in results if sample[0][0] == 1 and sample[1] == 0]

    if len(benign) > 0:
        fp = float(len(fps)) / float(len(benign))
    else:
        fp = 'N/A'
    if len(malicious) > 0:
        fn = float(len(fns)) / float(len(malicious))
    else:
        fn = 'N/A'

    logger.log_info(module_name, "----------")
    logger.log_info(module_name, "FP: " + str(fp))
    logger.log_info(module_name, "FN: " + str(fn))
    logger.log_info(module_name, "----------")

    # Saving CSV
    if not options.csv is None:
        logger.log_info(module_name, "Saving CSV to " + options.csv)
        try:
            with open(options.csv, 'w') as csv_file:
                csv_file.write("true_label,pred_label,avg_accuracy,avg_confidence,name\n")
                for result in results:
                    csv_file.write(','.join([str(result[0][0]), str(result[1][0]), str(result[0][1]), str(result[0][2]), result[0][3]]) + "\n")
        except Exception as ex:
            module.log_error(module_name, "Failed to save CSV: " + str(ex))

    # Saving Classifier
    if not options.save is None:
        logger.log_info(module_name, "Saving classifier to " + options.save)
        try:
            joblib.dump(svm, options.save)
        except:
            logger.log_error(module_name, "Failed to save classifier to " + options.save)

    # Plotting
    if not options.plot is None:
        logger.log_info(module_name, "Saving plot to " + options.plot)
        axes = plt.gca()
        axes.set_xlim([0, 1])
        axes.set_ylim([0, 1])
        w = svm.coef_[0]
        a = -w[0] / w[1]
        xx = np.linspace(0, 1)
        yy = a * xx - (svm.intercept_[0]) / w[1]
        plt.scatter([sample[0][1] for sample in benign], [sample[0][2] for sample in benign], marker='o', c='blue', s=20)
        plt.scatter([sample[0][1] for sample in malicious], [sample[0][2] for sample in malicious], marker='x', c='red', s=20)
        plt.plot(xx, yy, 'k--')
        plt.xlabel('Wrong Prediction (%)')
        plt.ylabel('Average Confidence (%)')
        try:
            plt.savefig(options.plot)
        except:
            logger.log_error(module_name, "Failed to save plot")

    # ROC
    if not options.roc is None:
        logger.log_info(module_name, "Saving ROC to " + options.roc)
        make_roc(options.roc, data, svm)

    logger.log_stop()

if __name__ == '__main__':
    main()
