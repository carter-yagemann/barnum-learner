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

import json
import tempfile
import requests
from requests.packages.urllib3.exceptions import SubjectAltNameWarning

# Configuration
api_url = 'https://localhost:5000'
api_key = 'AAAABBBBCCCCDDDD'
api_cert = """-----BEGIN CERTIFICATE-----
MIIF9jCCA96gAwIBAgIJAL5TwC2GVD5HMA0GCSqGSIb3DQEBCwUAMIGPMQswCQYD
VQQGEwJVUzEQMA4GA1UECAwHR2VvcmdpYTEQMA4GA1UEBwwHQXRsYW50YTEVMBMG
A1UECgwMR2VvcmdpYSBUZWNoMQ0wCwYDVQQLDARJSVNQMRIwEAYDVQQDDAlsb2Nh
bGhvc3QxIjAgBgkqhkiG9w0BCQEWE3lhZ2VtYW5uQGdhdGVjaC5lZHUwHhcNMTgw
NDI3MTU0MzAyWhcNMTkwNDI3MTU0MzAyWjCBjzELMAkGA1UEBhMCVVMxEDAOBgNV
BAgMB0dlb3JnaWExEDAOBgNVBAcMB0F0bGFudGExFTATBgNVBAoMDEdlb3JnaWEg
VGVjaDENMAsGA1UECwwESUlTUDESMBAGA1UEAwwJbG9jYWxob3N0MSIwIAYJKoZI
hvcNAQkBFhN5YWdlbWFubkBnYXRlY2guZWR1MIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEA8MBsKzMSOeFn8ZyZcFnbXrFD4/XKe0WKdMijrv0qsEPKN6vx
YisMoMvxwPiDW67APRmMNf2GVyyzhmSNVOOKV3FH2boP13IAO0xfOuRBWOWSBABT
BSK8r4zePZ+Z+DkzSbNqifS/jimjB95MM783KREgbT2FXutXL4WX0UVfDLeFrqMJ
/2+Ub3OnPzxWm5U0HVm/TLEEPRI8KBgeKiAlP1ER5zRzogqBSuT9ByupUGzhJmE1
+8AhpCAwYnSB1+QxjPn3lxxrc0T/wfDHeZ9jdI5c1kYL/N2xCK5UYYKFsXOtkodD
OQCYDGT9/0PGTT7eQ6smyYX1HmYhy3/YRXcDqHnZMGh2ctPuldaAgfOPuua2EaFq
lX11u70mm8VHRRu0jPt0y/Ve5CC/hcoQIEsc7+++6GyCfBA3GAoPpxelUXc8mLMy
dlHXyAu/rbAUrsUa86R/FEE4KtOQnk1MDRheoRS5zjv63V2p5RgdGtVNliQzmiaw
TlzWitdlALIiWKNQ4BN7MIfBaN+bP4sb/51Y1cEwaYh2v0lshxJtVKzOwqDE72f/
5FSlQ/VHnhJRZXTYlvQYf737IaM6YRRq0fGdgvkQIaWC2LZpmUxLssa6iqSe1DJn
TPWfm4VqV4tVdmzNZyOAK5zgu7FqHTQPHs+39uiJ1s1T8q8YVKwQZLW7otkCAwEA
AaNTMFEwHQYDVR0OBBYEFFUif58KXPVf/pY9Yck2xqC4aOu7MB8GA1UdIwQYMBaA
FFUif58KXPVf/pY9Yck2xqC4aOu7MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN
AQELBQADggIBAFyBroI6wfW7ktWa48V4gCyX6iAF2G5oGihuDZaG0JbdaxaBw8uh
hXXMowx34PzxoVMAnDzBbqw48mhUSNklyVkFjGXkF1u00TaHtGxIw6M8LldzArRY
YKIbSHC6Ej8I/Wkibf6lbnKGYT2frPOdoMngFI1OMhxTxj3RBP06iYNxkD5hmnOQ
HLQkNuz0m0bq18fakBxQD+L8791qj8z1ca/zmnM4UUEZqcJcPLPiBg9AiSt30p6b
xd4lXg6SDDaa++iF0K94mUc6P364j74l4BN5D5YG64pDOVUY9m4mxhOB4WrEMIi6
AVLby67WWWqPmU5NlYVlWh6C5qdu0ciAO0QZgw36cIZtDYtPacgdtwppA+bs+9Na
YUoqXMK6iPwKs5oMT+/ak3almOjrHEmrdENVC1jaA1QBSQn1qhOFF61WK2/kpwO+
0VtR4ojn1N0UM6qGH/xdMEKXBQEIIrLX3a81DrBzHdt6Zbdws3mQN1M8avBm+UWq
bBAsyF6wFKBztaD099UluXLpLH5B5LILoVrgABJ+oRCfWHYiYIxJfkZm9sCfmHwL
HHYhr2h1omYxxU1ChfarteYpOkrhczxoAVNeP0k8O9FqmfxQVunquiFTJNZiZ/Qn
4rKGKiHhoUcOsPcinuKfH285snqOID59OoIjlbuvgzQzqkuVLa6YSX2v
-----END CERTIFICATE-----
"""

lstmpt_check_cache = dict()
lstmpt_result_cache = dict()

class LSTMPT:
    """A module for interfacing the MLSploit WebUI with LSTM-PT"""

    def __init__(self):
        """Initialize this module"""

        self.obj_type = "PT"

        # Public function parameters
        self.params_t_train_lstm = {
            "num_epoch": "integer",
        }
        self.params_p_transform_lstm = {}
        self.params_e_evaluate_lstm= {}

        # Unpack the server's HTTPS certificate so requests can use it
        fd, ofile = tempfile.mkstemp()
        with open(ofile, 'w') as certfile:
            certfile.write(api_cert)
        self.certfile = ofile

        # Disable warning about SubjectAltName, server cert uses CommonName
        requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

        lstmpt_status = dict()

    def _objs2traces(self, obj_list):
        """Converts a list of obj to trace record locators"""
        res = list()
        for obj in obj_list:
            try:
                with open(obj.obj_file, 'r') as ifile:
                    res.append(ifile.read().strip())
            except:
                continue
        return res

    def t_train_lstm(self, obj, train_job_id, **kwargs):
        """Train a LSTM model"""
        req = {
            "api_key": api_key,
            "num_epoch": kwargs['num_epoch'],
            "job_id": train_job_id,
            "traces": self._objs2traces(obj),
        }

        res = requests.post(api_url + '/train', json=req, verify=self.certfile)
        if res.status_code != 200:
            return False

        return True

    def p_transform_lstm(self, obj, transform_job_id, **kwargs):
        """Transform a LSTM sample set"""
        # This module does not support transform
        return False

    def e_evaluate_lstm(self, obj, evaluate_job_id, **kwargs):
        """Evaluate a LSTM model"""
        req = {
            "api_key": api_key,
            "job_id": evaluate_job_id,
            "traces": self._objs2traces([obj]),
        }

        res = requests.post(api_url + '/evaluate', json=req, verify=self.certfile)
        if res.status_code != 200:
            return False

        return True

    def check(self, job_type, job_id):
        """Check the status of a job"""
        # Cache so we don't keep querying the backend for statuses that won't change
        status_key = str(job_type) + ":" + str(job_id)
        if status_key in lstmpt_check_cache.keys():
            return lstmpt_check_cache[status_key]

        req = {
            "api_key": api_key,
            "job_type": job_type,
            "job_id": job_id,
        }

        res = requests.post(api_url + '/check', json=req, verify=self.certfile)
        if res.status_code != 200:
            result = 'FAILED'
        else:
            result = res.json()['status']

        # If status is final, add to cache
        if not result in ['PENDING', 'STARTED']:
            lstmpt_check_cache[status_key] = result

        return result

    def get_log(self, job_type, job_id):
        """Get the log for a job"""
        req = {
            "api_key": api_key,
            "job_type": job_type,
            "job_id": job_id,
        }

        res = requests.post(api_url + '/log', json=req, verify=self.certfile)
        if res.status_code != 200:
            result = "Unexpected response: " + str(res.status_code) + "\n"
        else:
            result = res.json()['result']

        return result

    def get_result(self, job_type, job_id):
        """Get the results for a job"""
        # Cache so we don't keep querying the backend for statuses that won't change
        status_key = str(job_type) + ":" + str(job_id)
        if status_key in lstmpt_result_cache.keys():
            return lstmpt_result_cache[status_key]

        req = {
            "api_key": api_key,
            "job_type": job_type,
            "job_id": job_id,
        }

        res = requests.post(api_url + '/result', json=req, verify=self.certfile)
        if res.status_code != 200:
            result = None
        else:
            result = res.json()['result']

        # If status is final, add to cache
        if not result is None:
            lstmpt_result_cache[status_key] = result

        return result

    def get_info_t(self):
        """Get training documentation"""
        return 'Trains a LSTM-PT model. Only additional parameter is max number of epoches to train over.'

    def get_info_p(self):
        """Get transforming documentation"""
        return 'This module does not support transformations.'

    def get_info_e(self):
        """Get evaluation documentation"""
        return 'Evaluates the last trained model for prediction accuracy. No additional options.'
