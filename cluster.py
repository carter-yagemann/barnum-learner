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
from sklearn.cluster import DBSCAN
import matplotlib
matplotlib.use('Agg')  # Hack so X isn't required
import matplotlib.pyplot as plt
from matplotlib.path import Path
from matplotlib.spines import Spine
from matplotlib.projections.polar import PolarAxes
from matplotlib.projections import register_projection

module_name = 'Cluster'
module_version = '1.0.0'

# Error Codes
ERROR_INVALID_ARG = 1
ERROR_RUNTIME     = 2

def radar_factory(num_vars, frame='circle'):
    """Create a radar chart with `num_vars` axes.

    This function creates a RadarAxes projection and registers it.

    Parameters
    ----------
    num_vars : int
        Number of variables for radar chart.
    frame : {'circle' | 'polygon'}
        Shape of frame surrounding axes.

    """
    # calculate evenly-spaced axis angles
    theta = np.linspace(0, 2*np.pi, num_vars, endpoint=False)

    def draw_poly_patch(self):
        # rotate theta such that the first axis is at the top
        verts = unit_poly_verts(theta + np.pi / 2)
        return plt.Polygon(verts, closed=True, edgecolor='k')

    def draw_circle_patch(self):
        # unit circle centered on (0.5, 0.5)
        return plt.Circle((0.5, 0.5), 0.5)

    patch_dict = {'polygon': draw_poly_patch, 'circle': draw_circle_patch}
    if frame not in patch_dict:
        raise ValueError('unknown value for `frame`: %s' % frame)

    class RadarAxes(PolarAxes):

        name = 'radar'
        # use 1 line segment to connect specified points
        RESOLUTION = 1
        # define draw_frame method
        draw_patch = patch_dict[frame]

        def __init__(self, *args, **kwargs):
            super(RadarAxes, self).__init__(*args, **kwargs)
            # rotate plot such that the first axis is at the top
            self.set_theta_zero_location('N')

        def fill(self, *args, **kwargs):
            """Override fill so that line is closed by default"""
            closed = kwargs.pop('closed', True)
            return super(RadarAxes, self).fill(closed=closed, *args, **kwargs)

        def plot(self, *args, **kwargs):
            """Override plot so that line is closed by default"""
            lines = super(RadarAxes, self).plot(*args, **kwargs)
            for line in lines:
                self._close_line(line)

        def _close_line(self, line):
            x, y = line.get_data()
            if x[0] != x[-1]:
                x = np.concatenate((x, [x[0]]))
                y = np.concatenate((y, [y[0]]))
                line.set_data(x, y)

        def set_varlabels(self, labels):
            self.set_thetagrids(np.degrees(theta), labels)

        def _gen_axes_patch(self):
            return self.draw_patch()

        def _gen_axes_spines(self):
            if frame == 'circle':
                return PolarAxes._gen_axes_spines(self)
            # The following is a hack to get the spines (i.e. the axes frame)
            # to draw correctly for a polygon frame.

            # spine_type must be 'left', 'right', 'top', 'bottom', or `circle`.
            spine_type = 'circle'
            verts = unit_poly_verts(theta + np.pi / 2)
            # close off polygon by repeating first vertex
            verts.append(verts[0])
            path = Path(verts)

            spine = Spine(self, spine_type, path)
            spine.set_transform(self.transAxes)
            return {'polar': spine}

    register_projection(RadarAxes)
    return theta


def unit_poly_verts(theta):
    """Return vertices of polygon for subplot axes.

    This polygon is circumscribed by a unit circle centered at (0.5, 0.5)
    """
    x0, y0, r = [0.5] * 3
    verts = [(r*np.cos(t) + x0, r*np.sin(t) + y0) for t in theta]
    return verts

def parse_file(args):
    """Parse a single evaluation file"""
    ifilepath, max_classes = args
    name = os.path.basename(ifilepath)

    anomalies = [0] * max_classes
    with gzip.open(ifilepath, 'rt') as ifile:
        try:
            for line in ifile:
                # format: "correct,pred_bin,confidence,real_bin\n"
                parts = line.split(',')
                if not int(parts[0]):
                    anomalies[int(parts[1]) % max_classes] += 1
        except (IOError, EOFError):
            logger.log_error(module_name, 'WARNING: Failed to parse %s' % ifilepath)
            return None

    # return numpy array of percentages
    return (np.array(anomalies, dtype=np.single) / sum(anomalies), name)

def main():
    """Main"""
    parser = OptionParser(usage='Usage: %prog [options] eval_dir', version='Barnum Cluster ' + module_version)
    parser.add_option('-c', '--csv', action='store', type='str', default=None,
                      help='Save CSV of results to given filepath (default: no CSV)')
    parser.add_option('-p', '--plot', action='store', type='str', default=None,
                      help='Save plot as a PNG image to the given filepath (default: no plotting)')
    parser.add_option('-w', '--workers', action='store', dest='workers', type='int', default=cpu_count(),
                      help='Number of workers to use (default: number of cores)')
    parser.add_option('--max-classes', action='store', type='int', default=256,
                      help='How many classes to use (default: 256)')
    parser.add_option('--min-samples', action='store', type='int', default=4,
                      help='Minimum samples to form a cluster in DBSCAN (default: 4)')
    parser.add_option('--eps', action='store', type='float', default=0.03,
                      help='Epsilon parameter to DBSCAN (default: 0.03)')

    options, args = parser.parse_args()

    if len(args) != 1 or options.workers < 1:
        parser.print_help()
        sys.exit(ERROR_INVALID_ARG)

    logger.log_start(20)
    logger.log_info(module_name, 'Barnum Cluster %s' % module_version)

    idirpath = args[0]

    if not os.path.isdir(idirpath):
        logger.log_error(module_name, 'ERROR: %s is not a directory' % idirpath)
        logger.log_stop()
        sys.exit(ERROR_INVALID_ARG)

    files = [os.path.join(idirpath, f) for f in os.listdir(idirpath) if os.path.isfile(os.path.join(idirpath, f))]
    # We only care about clustering malicious traces
    mal_files = [fp for fp in files if 'malicious' in os.path.basename(fp)]
    num_mal = len(mal_files)

    # Calculate clustering metrics
    logger.log_info(module_name, "Parsing " + idirpath)
    pool = Pool(options.workers)
    data = [sample for sample in pool.map(parse_file, zip(mal_files, [options.max_classes] * num_mal)) if sample]
    pool.close()
    xs = np.array([sample[0] for sample in data])
    ns = [sample[1] for sample in data]

    # Clustering
    logger.log_info(module_name, "Calculating clusters")
    db = DBSCAN(eps=options.eps, min_samples=options.min_samples).fit(xs)
    core_samples_mask = np.zeros_like(db.labels_, dtype=bool)
    core_samples_mask[db.core_sample_indices_] = True
    labels = db.labels_

    # Number of clusters in labels, ignoring noise if present.
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    logger.log_info(module_name, '      Number of points: %d' % len(ns))
    logger.log_info(module_name, '    Number of clusters: %d' % n_clusters)
    logger.log_info(module_name, 'Number of noise points: %d' % n_noise)

    # Saving results as CSV
    if not options.csv is None:
        logger.log_info(module_name, "Saving CSV to %s" % options.csv)
        try:
            with open(options.csv, 'w') as csv_file:
                csv_file.write("cluster,filename\n")
                for label, name in zip(labels, ns):
                    csv_file.write(','.join([str(label), name]) + "\n")
        except Exception as ex:
            logger.log_error(module_name, "Failed to save CSV: %s" % str(ex))

    # Saving results as plot image
    if not options.plot is None:
        logger.log_info(module_name, "Generating plot")
        theta = radar_factory(options.max_classes, frame='polygon')
        fig, axes = plt.subplots(subplot_kw=dict(projection='radar'))
        colors = ['b', 'r', 'g', 'm', 'y']
        axes.set_varlabels([""])  # no varlabels, they aren't that meaningful
        axes.set_rgrids([0.2, 0.4, 0.6, 0.8])
        legend_labels = list()
        for label_key in set(labels):
            if label_key == -1:
                continue  # noise
            legend_labels.append(label_key)
            label_color = colors[label_key % len(colors)]
            # Calculate per-cluster average
            label_mask = (labels == label_key)
            label_points = xs[label_mask & core_samples_mask]
            label_means = np.mean(label_points, axis=0)
            axes.plot(theta, label_means, color=label_color)
            axes.fill(theta, label_means, facecolor=label_color, alpha=0.25)
        # Legend
        legend = axes.legend(legend_labels, loc=(0.9, .95),
                             labelspacing=0.1, fontsize='small')

        try:
            plt.savefig(options.plot)
        except:
            logger.log_error(module_name, "Failed to save plot")

    logger.log_stop()

if __name__ == '__main__':
    main()
