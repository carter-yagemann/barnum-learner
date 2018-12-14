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
from multiprocessing import Pool, cpu_count
import numpy as np
from sklearn.svm import SVC
import matplotlib
matplotlib.use('Agg')  # Hack so X isn't required
import matplotlib.pyplot as plt
from sklearn.externals import joblib

module_name = 'Classifier'
module_version = '1.0.2'

# Error Codes
ERROR_INVALID_ARG = 1
ERROR_RUNTIME     = 2

def parse_file(ifilepath):
    """Parse a single evaluation file"""
    name = os.path.basename(ifilepath)

    if 'malicious' in name:
        label = 1
    elif 'benign' in name:
        label = 0
    else:
        return (3, 0, 0, name)

    with gzip.open(ifilepath, 'rt') as ifile:
        try:
            parts = [line.strip().split(',') for line in ifile.readlines()]
            accuracy = [int(part[0]) for part in parts]
            confidence = [float(part[2]) for part in parts if part[0] == '0']
        except IOError:
            logger.log_error(module_name, 'WARNING: Failed to parse ' + ifilepath)
            return (3, 0, 0, name)

    if len(accuracy) == 0 or len(confidence) == 0:
        return (3, 0, 0, name)

    avg_accuracy = 1.0 - float(sum(accuracy)) / float(len(accuracy))
    avg_confidence = float(sum(confidence)) / float(len(confidence))

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
    parser.add_option('-w', '--workers', action='store', dest='workers', type='int', default=cpu_count(),
                      help='Number of workers to use (default: number of cores)')

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

    # Calculate average accuracy and confidence for each sample
    pool = Pool(options.workers)
    data = [sample for sample in pool.map(parse_file, files) if sample[0] < 2]
    ys = np.array([sample[0] for sample in data])
    xs = np.array([sample[1:3] for sample in data])

    if options.load is None:
        # Train a new classifier from scratch
        if options.force:
            # SVM (we're going to force it to have 0 FP)
            fp = 1.0
            weight = 10.0

            while fp > 0.0 and weight > 0.0000001:

                svm = SVC(kernel='linear', class_weight={0: 1.0, 1: weight})
                svm.fit(xs, ys)
                weight *= 0.999

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
        fp = 0.0
    if len(malicious) > 0:
        fn = float(len(fns)) / float(len(malicious))
    else:
        fn = 0.0

    logger.log_info(module_name, "----------")
    logger.log_info(module_name, "FP: " + str(fp))
    logger.log_info(module_name, "FN: " + str(fn))

    logger.log_info(module_name, "False Negatives:")
    for sample in fns:
        logger.log_info(module_name, '    ' + str(sample[0][3]))
    logger.log_info(module_name, "----------")

    # Saving CSV
    if not options.csv is None:
        logger.log_info(module_name, "Saving CSV to " + options.csv)
        try:
            with open(options.csv, 'w') as csv_file:
                csv_file.write("true_label,pred_label,name\n")
                for result in results:
                    csv_file.write(','.join([str(result[0][0]), str(result[1][0]), result[0][3]]) + "\n")
        except Exception as ex:
            module.log_error(module_name, "Failed to save CSV: " + str(ex))

    # Saving Classifier
    if not options.save is None:
        logger.log_info(module_name, "Saving classifier")
        try:
            joblib.dump(svm, options.save)
        except:
            logger.log_error(module_name, "Failed to save classifier to " + options.save)

    # Plotting
    if not options.plot is None:
        axes = plt.gca()
        axes.set_xlim([0, 1])
        axes.set_ylim([0, 1])
        w = svm.coef_[0]
        a = -w[0] / w[1]
        xx = np.linspace(0, 1)
        yy = a * xx - (svm.intercept_[0]) / w[1]
        plt.scatter([sample[0][1] for sample in benign], [sample[0][2] for sample in benign], marker='o', c='blue')
        plt.scatter([sample[0][1] for sample in malicious], [sample[0][2] for sample in malicious], marker='x', c='red')
        plt.plot(xx, yy, 'k--')
        plt.xlabel('Wrong Prediction (%)')
        plt.ylabel('Average Confidence (%)')
        try:
            plt.savefig(options.plot)
        except:
            logger.log_error(module_name, "Failed to save plot")

    logger.log_stop()

if __name__ == '__main__':
    main()
