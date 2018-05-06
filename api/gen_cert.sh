#!/bin/bash

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -sha256

echo "Don't forget to add the contents of cert.pem to lstm_pt_module.py (see variable api_cert)"
