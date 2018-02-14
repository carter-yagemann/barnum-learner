#!/usr/bin/env python

import logger
import subprocess

def lookup_bin(name):
    p = subprocess.Popen(['which', name], stdout=subprocess.PIPE)
    return p.stdout.read().strip()
