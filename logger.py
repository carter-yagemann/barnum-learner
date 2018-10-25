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

import logging
from multiprocessing import Process, Queue, Value

def log_debug(module_name, message):
    global logging_queue
    logging_queue.put({'level': 0, 'module_name': module_name, 'message': message})

def log_info(module_name, message):
    global logging_queue
    logging_queue.put({'level': 1, 'module_name': module_name, 'message': message})

def log_warning(module_name, message):
    global logging_queue
    logging_queue.put({'level': 2, 'module_name': module_name, 'message': message})

def log_error(module_name, message):
    global logging_queue
    logging_queue.put({'level': 3, 'module_name': module_name, 'message': message})

def log_critical(module_name, message):
    global logging_queue
    logging_queue.put({'level': 4, 'module_name': module_name, 'message': message})

def log_start(level):
    global logger
    global logging_queue
    global logger_running
    global logger_process

    FORMAT = '%(asctime)-15s [%(level)s][%(module_name)s] %(message)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('pdf-pt-learner')
    logger.setLevel(level)
    logging_queue = Queue()
    logger_running = Value('b', True)

    logger_process = Process(target=log_worker)
    logger_process.start()

def log_stop():
    global logger_running
    global logger_process

    logger_running.value = False
    logger_process.join()

def log_worker():
    global logger
    global logger_running
    global logging_queue

    while True:
        try:
            msg = logging_queue.get(True, 5)
        except:
            if logger_running.value:
                continue
            else:
                return
        if msg['level'] == 0:
            logger.debug(msg['message'], extra={'level': 'D', 'module_name': msg['module_name']})
        elif msg['level'] == 1:
            logger.info(msg['message'], extra={'level': 'I', 'module_name': msg['module_name']})
        elif msg['level'] == 2:
            logger.warning(msg['message'], extra={'level': 'W', 'module_name': msg['module_name']})
        elif msg['level'] == 3:
            logger.error(msg['message'], extra={'level': 'E', 'module_name': msg['module_name']})
        elif msg['level'] == 4:
            logger.critical(msg['message'], extra={'level': 'C', 'module_name': msg['module_name']})

def test_logging():
    name = 'Tester'

    log_start(logging.DEBUG)

    log_debug(name, 'This is a debug message')
    log_info(name, 'This is an info message')
    log_warning(name, 'This is a warning message')
    log_error(name, 'This is an error message')
    log_critical(name, 'This is a critical message')

    log_stop()

if __name__ == '__main__':
    test_logging()
