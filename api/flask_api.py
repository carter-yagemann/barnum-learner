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

import os
import sys
import json
import tempfile
import ssl
from multiprocessing import Queue
from optparse import OptionParser
from copy import deepcopy
from flask import *
import api_worker

app = Flask('LSTM-PT API')

api_keys = list()
tasks = dict()

data_dir = tempfile.mkdtemp(prefix="lstm-pt-flask-")
model_path = os.path.join(data_dir, 'model.json')
weights_path = os.path.join(data_dir, 'weights.h5')

res_okay  = {'response': {'code': 0, 'description': 'OK'}}
res_error = {'response': {'code': 1, 'description': 'ERROR'}}

# Mapping from Celery status to WebUI status
status_map = {
    'PENDING': 'PENDING',
    'STARTED': 'STARTED',
    'RETRY':   'UNSUCCESSFUL',
    'FAILURE': 'UNSUCCESSFUL',
    'SUCCESS': 'SUCCESSFUL',
}

def parse_api_keys(filepath):
    global api_keys

    with open(filepath, 'r') as ifile:
        api_keys = [key.strip() for key in ifile]

def validate_request(data):
    if data is None:
        return False
    if not 'api_key' in data.keys():
        return False
    if data['api_key'] in api_keys:
        return True
    return False

def create_set(list, label):
    if len(list) < 1:
        return None

    fd, ofile = tempfile.mkstemp(prefix="set-" + label + '-', dir=data_dir)
    fd = os.fdopen(fd, 'w')
    fd.write('[' + label + "]\n")
    for name in list:
        name_path = os.path.join(options.trace_dir, name)
        if not os.path.isdir(name_path):
            continue
        fd.write(name_path + "\n")

    # Hack: lstm.py expects the other labels to be defined, but
    # since we'll only do training XOR testing, we can just place
    # anything in these sections
    if label != 'b_train':
        fd.write("[b_train]\n")
        fd.write(os.path.join(options.trace_dir, list[0]) + "\n")

    if label != 'b_test':
        fd.write("[b_test]\n")
        fd.write(os.path.join(options.trace_dir, list[0]) + "\n")

    if label != 'm_test':
        fd.write("[m_test]\n")
        fd.write(os.path.join(options.trace_dir, list[0]) + "\n")

    fd.close()
    return ofile

@app.route('/train', methods=['POST'])
def train():
    data = request.get_json(force=True, silent=True)
    if not validate_request(data):
        return json.dumps(res_error), 401

    for param in ['num_epoch', 'traces', 'job_id']:
        if not param in data.keys():
            return json.dumps(res_error), 400

    key = str(request.remote_addr) + ':TRAIN:' + str(data['job_id'])

    set_file = create_set(data['traces'], 'b_train')
    if set_file is None:
        return json.dumps(res_error), 400

    cmd = [options.lstm_prog, '--status-interval', '3600', '--skip-test', '--skip-eval',
           '-p', '-i', set_file, '-e', str(data['num_epoch']),
           '--save-model', model_path, '--save-weights', weights_path,
           options.trace_dir, options.bin_dir]
    fd, ofile = tempfile.mkstemp(prefix='res-', dir=data_dir)

    if options.debugging:
        job = api_worker.dry_run_lstm.delay(cmd, ofile)
    else:
        job = api_worker.run_lstm.delay(cmd, ofile)

    tasks[key] = (job, ofile)

    return json.dumps(res_okay), 200

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json(force=True, silent=True)
    if not validate_request(data):
        return json.dumps(res_error), 401

    for param in ['job_id', 'traces']:
        if not param in data.keys():
            return json.dumps(res_error), 400

    if not options.debugging:
        if not os.path.isfile(model_path):
            return json.dumps(res_error), 400
        if not os.path.isfile(weights_path):
            return json.dumps(res_error), 400

    key = str(request.remote_addr) + ':EVALUATE:' + str(data['job_id'])

    set_file = create_set(data['traces'], 'b_test')
    if set_file is None:
        return json.dumps(res_error), 400

    cmd = [options.lstm_prog, '--status-interval', '3600', '--skip-eval',
           '-p', '-i', set_file, '--use-model', model_path, '--use-weights', weights_path,
           options.trace_dir, options.bin_dir]
    fd, ofile = tempfile.mkstemp(prefix='res-', dir=data_dir)

    if options.debugging:
        job = api_worker.dry_run_lstm.delay(cmd, ofile)
    else:
        job = api_worker.run_lstm.delay(cmd, ofile)

    tasks[key] = (job, ofile)

    return json.dumps(res_okay), 200

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json(force=True, silent=True)
    if not validate_request(data):
        return json.dumps(res_error), 401

    for param in ['job_type', 'job_id']:
        if not param in data.keys():
            return json.dumps(res_error), 400

    key = str(request.remote_addr) + ':' + str(data['job_type']) + ':' + str(data['job_id'])

    if not key in tasks.keys():
        status = 'FAILED'
    else:
        status = status_map[tasks[key][0].status]

    res = deepcopy(res_okay)
    res['status'] = status

    return json.dumps(res), 200

@app.route('/result', methods=['POST'])
def get_result():
    data = request.get_json(force=True, silent=True)
    if not validate_request(data):
        return json.dumps(res_error), 401

    for param in ['job_type', 'job_id']:
        if not param in data.keys():
            return json.dumps(res_error), 400

    key = str(request.remote_addr) + ':' + str(data['job_type']) + ':' + str(data['job_id'])

    if not key in tasks.keys():
        return json.dumps(res_error), 400

    if not tasks[key][0].successful():
        return json.dumps(res_error), 400

    res = deepcopy(res_okay)
    res['result'] = 'done'

    return json.dumps(res), 200

@app.route('/log', methods=['POST'])
def get_log():
    data = request.get_json(force=True, silent=True)
    if not validate_request(data):
        return json.dumps(res_error), 401

    for param in ['job_type', 'job_id']:
        if not param in data.keys():
            return json.dumps(res_error), 400

    key = str(request.remote_addr) + ':' + str(data['job_type']) + ':' + str(data['job_id'])

    if not key in tasks.keys():
        return json.dumps(res_error), 400

    if not tasks[key][0].successful():
        return json.dumps(res_error), 400

    res = deepcopy(res_okay)
    with open(tasks[key][1], 'r') as ifile:
        res['result'] = ifile.read()

    return json.dumps(res), 200

if __name__ == '__main__':

    parser = OptionParser(usage="Usage: %prog [options]")
    parser.add_option('-a', '--api-keys', action='store', dest='api_keys_file', type='str', default='./api_keys',
                      help='Path to API keys file (default: ./api_keys)')
    parser.add_option('-t', '--trace-dir', action='store', dest='trace_dir', type='str', default='./traces',
                      help='Path to traces directory (default: ./traces)')
    parser.add_option('-b', '--bin-dir', action='store', dest='bin_dir', type='str', default='./bin',
                      help='Path to binaries directory (default: ./bin)')
    parser.add_option('-l', '--lstm', action='store', dest='lstm_prog', type='str', default='../lstm.py',
                      help='Path to lstm.py (default: ../lstm.py)')
    parser.add_option('-d', '--debug', action='store_true', dest='debugging',
                      help='Run in debugging mode (lstm.py will not actually be called)')
    parser.add_option('--bind', action='store', dest='bind', type='str', default='localhost',
                      help='The address to bind to (default: localhost)')
    parser.add_option('-p', '--port', action='store', dest='port', type='int', default=5000,
                      help='The port to bind to (default: 5000)')
    parser.add_option('-c', '--cert', action='store', dest='cert', type='str', default='./cert.pem',
                      help='Certificate to use for HTTPS (default: ./cert.pem)')
    parser.add_option('-k', '--key', action='store', dest='key', type='str', default='./key.pem',
                      help='Private key to use for HTTPS (default: ./key.pem)')

    options, args = parser.parse_args()
    parse_api_keys(options.api_keys_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(options.cert, options.key)

    app.run(host=options.bind, port=options.port, debug=False, use_evalex=False, ssl_context=context)
