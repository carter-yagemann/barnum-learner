#!/usr/bin/env python

import sys
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Hack so X isn't required
import matplotlib.pyplot as plt
import gzip
from multiprocessing import Pool

def parse_file(ifilepath):
    """Parse a single evaluation file"""
    ofilepath = os.path.join(odirpath, os.path.basename(ifilepath) + '.png')

    scatters = {'0x': list(),
                '0y': list(),
                '1x': list(),
                '1y': list(),
               }

    try:
        with gzip.open(ifilepath, 'r') as ifile:
            for line in ifile:
                res, guess, conf = line.strip().split(',')
                try:
                    scatters[res+'x'].append(float(guess))
                    scatters[res+'y'].append(float(conf))
                except KeyError, ValueError:
                    print 'WARNING: Unexpected values (', res, guess, conf, ')'
                    continue
    except IOError:
        print 'WARNING: Failed to parse', ifilepath
        return (2, 0, 0)

    # Graph some plots for this lone evaluation
    total = len(scatters['0y']) + len(scatters['1y'])
    per_0 = round(float(len(scatters['0y'])) / float(total), 4)
    per_1 = round(float(len(scatters['1y'])) / float(total), 4)
    avg_0 = sum(scatters['0y']) / len(scatters['0y'])
    avg_1 = sum(scatters['1y']) / len(scatters['1y'])
    max_0 = max(scatters['0x'])
    max_1 = max(scatters['1x'])

    f, axes = plt.subplots(1, 2, sharex=True, sharey=True, figsize=(20, 10))

    axes[0].set_xlim([0,max_0])
    axes[0].set_ylim([0,1])
    axes[1].set_xlim([0,max_1])
    axes[1].set_ylim([0,1])

    axes[0].scatter(scatters['0x'], scatters['0y'], c='red')
    axes[1].scatter(scatters['1x'], scatters['1y'], c='blue')

    axes[0].plot([0, max_0], [avg_0, avg_0], linewidth=5, c='y')
    axes[1].plot([0, max_1], [avg_1, avg_1], linewidth=5, c='y')

    axes[0].set_title('Wrong Predictions (' + str(per_0) + ')')
    axes[1].set_title('Correct Predictions (' + str(per_1) + ')')

    f.savefig(ofilepath)
    plt.close(f)

    # Return some info that will be used to make the summary plot
    if 'malicious' in os.path.basename(ifilepath):
        return (1, per_0, avg_0)
    elif 'benign' in os.path.basename(ifilepath):
        return (0, per_0, avg_0)
    else:
        return (2, per_0, avg_0)

def main():
    """Main"""
    global odirpath

    if len(sys.argv) != 3:
        print 'Usage:', sys.argv[0], '<eval_dir>', '<output_dir>'
        sys.exit()

    idirpath = sys.argv[1]
    odirpath = sys.argv[2]

    if not os.path.isdir(idirpath):
        print 'ERROR:', idirpath, 'is not a directory'
        sys.exit(1)

    if not os.path.isdir(odirpath):
        print 'ERROR:', odirpath, 'is not a directory'
        sys.exit(1)

    scatters = {'0x': list(),
                '0y': list(),
                '1x': list(),
                '1y': list(),
               }

    files = [os.path.join(idirpath, f) for f in os.listdir(idirpath) if os.path.isfile(os.path.join(idirpath, f))]
    pool = Pool()
    res = pool.map(parse_file, files)

    for label, per, avg in res:
        if label == 0:
            scatters['0x'].append(per)
            scatters['0y'].append(avg)
        elif label == 1:
            scatters['1x'].append(per)
            scatters['1y'].append(avg)
        else:
            'WARNING: Unexpected label', label

    plt.scatter(scatters['0x'], scatters['0y'], marker='o', c='blue')
    plt.scatter(scatters['1x'], scatters['1y'], marker='x', c='red')

    plt.xlabel('Percent Wrong Prediction')
    plt.ylabel('Average Confidence')

    plt.savefig(os.path.join(odirpath, 'summary.png'))

if __name__ == '__main__':
    main()
