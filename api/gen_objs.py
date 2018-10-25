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

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'Usage:', sys.argv[0], '<trace_dir>', '<output_directory>'
        sys.exit(1)

    entries = os.listdir(sys.argv[1])
    odir = sys.argv[2]

    if not os.path.isdir(odir):
        print 'ERROR:', odir, 'does not exist or is not a directory'
        sys.exit(1)

    if len(os.listdir(odir)) > 0:
        print 'ERROR:', odir, 'is not empty'
        sys.exit(1)

    for entry in entries:
        entry_path = os.path.join(sys.argv[1], entry)
        if not os.path.isdir(entry_path):
            continue
        info_path = os.path.join(entry_path, 'info.txt')
        if not os.path.isfile(info_path):
            continue
        with open(info_path, 'r') as ifile:
            ifile.readline()  # original filename
            label = ifile.readline().strip()
        if label != 'benign':
            continue
        parsed_path = os.path.join(entry_path, 'trace_parsed.gz')
        if not os.path.isfile(parsed_path):
            continue
        ofilepath = os.path.join(odir, entry)
        with open(ofilepath, 'w') as ofile:
            ofile.write(entry)
