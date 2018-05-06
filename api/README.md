# Setup

You need to create two configuration files inside the `api` directory: `api_keys` and `celeryconfig.py`.

`api_keys` is a newline seperated list of API keys to accept. For example:

    AAAABBBBCCCCDDDD
    EEEEFFFFGGGGHHHH

Clients *must* provide a valid API key in order to communicate with the server.

`celeryconfig.py` configures the celery worker. For example:

    broker_url = 'redis://localhost:6379/0'
    result_backend = 'redis://localhost:6379/0'

Additionally, the client and server require a SSL key/cert pair to use. You can generate these with
`gen_cert.sh`. Note that the contents of `cert.pem` need to be copied into `lstm_pt_module.py` as
the `api_cert` parameter.

# Usage

In order to use this API, you'll need at least one celery worker and the Flask server.

## Celery Worker

You can start a celery worker like so:

    celery -A api_worker worker --loglevel=info -c 1

Note that in this example, concurrency is set to 1 because if `lstm.py` is using a GPU Keras backend and
there's only one GPU on the computer, only one task can run at a time.

## Flask API

Once at least one celery worker is running, `flask_api.py` can be ran. For more details, see:

    ./flask_api.py -h

## Available Traces

The WebUI expects a collection of "objects" (in this case, traces) that the user can refer to when
creating tasks. This is how the user specifies what to train on, test on, etc. Use `gen_objs.py` to
create these object files and then upload them into the WebUI.
