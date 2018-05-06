#!/usr/bin/env python

# Copyright 2018 Carter Yagemann.
# All rights reserved.

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
