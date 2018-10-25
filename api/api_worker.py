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

import time
import sys
import subprocess
from celery import Celery
import celeryconfig

app = Celery('lstm-pt-worker',
             config_source='celeryconfig')

@app.task
def run_lstm(cmd, ofile):
    with open(ofile, 'w') as fd:
        subprocess.call(cmd, stdout=fd, stderr=fd)

@app.task
def dry_run_lstm(cmd, ofile):
    with open(ofile, 'w') as fd:
        fd.write("LSTM-PT backend in debug mode, command that would have ran:\n")
        time.sleep(5)
        fd.write("    " + str(cmd) + "\n")
