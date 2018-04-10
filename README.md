# Installation

First, install a backend engine for Keras (e.g., Tensorflow). See Keras
documentation for more details. Then, install requirements:

    pip install -r requirements.txt

This code also requires the program `ptxed`, which is included in
the [libipt](https://github.com/01org/processor-trace) source code repo.
This can either be installed from source or using the following APT repo
maintained by the main author of this project:

    sh -c "$(wget -qO - https://super.gtisc.gatech.edu/libipt.sh)"
    sudo apt-get install ptxed

Finally, a Redis database is needed. Most GNU/Linux distributions already
have a package. For example, on Debian:

    sudo apt install redis-server

# Usage

See `./lstm.py --help` for options and usage.

## Redis

This system uses a Redis database to map program basic blocks to unique IDs
(referred to as BBIDs). By default, workers will try to connect to the default
Redis port on localhost and use database 0. This can be changed via the command
line options.

It is safe to reuse the database across sessions if the program being analyized
is the same. For different programs, the database should be flushed or a different
database number should be used. `redis-cli` makes flushing easy:

    redis-cli -n <dbnum> flushdb

Also keep in mind that if you want to save the model weights and reuse them later,
you will also need to keep the contents of the database used during training.
Flushing the database will cause new (and likely different) BBIDs to be asigned,
thereby making old weights invalid.

# Useful features

This section highlights some features that are useful in specific senarios.

## Logging

The `-l` flag allows you to set the logging level so you can dial how much
information is printed to the screen. By default, level 20 is used, which
includes info, warning, error, and critial. See usage for more info.

## Checkpointing

No one likes losing their model if a bug occurs during training. You can
configure this system to periodically save the current weights for the model
every couple of minutes like so:

    ./lstm.py --save-model=model.json --save-weights=weights.h5 --checkpoint=5 [... other args ...]

## Skipping training, testing, or evaluation

Somtimes you might only want to train and save the model because you're going
to run multiple evaluations with different parameters. This can be accomplished
like so:

    ./lstm.py --save-model=model.json --save-weights=weights.h5 --skip-test --skip-eval [... other args ...]

You can then run your testing and/or evaluation without needing to retrain:

    ./lstm.py --use-model=model.json --use-weights=weights.h5 [... other args ...]

## Performance

If you're using a GPU enabled framework, adjusting the batch size (`-b`) can
significantly improve performance.

## Reusing Previous Sets

By default, the system will randomly pick traces to create the training, test,
and evaluation sets. However, sometimes it's useful to reuse the sets picked
in a previous session (i.e., to compare different model settings). The selected
sets can be saved using the `-o` flag:

    ./lstm.py -o sets/my_sets.txt [... other args ...]

And reused in future sessions using the `-i` flag:

    ./lstm.py -i sets/my_sets.txt [... other args ...]

Note that even when using `-i`, you must still provide the system with the
correct root PT directory argument. Directories listed in the save file
that are outside the provided root PT directory will be skipped.

## Preprocessing

By default, the system will read in raw traces directly and preprocess them
on-the-fly before feeding them into the LSTM model for learning. This is the
most efficient way to handle the traces in terms of storage space, but requires
more CPU usage and more dependencies like Redis and `ptxed`.

Alternatively, `preprocess.py` can be used to (as the name suggests) read raw
traces and save preprocessed versions to storage. Using the `-p` flag in
`lstm.py` will cause the system to only use samples where a preprocessed
version of the trace is available. Note that the computer performing the
preprocessing will still need Redis and `ptxed`, but once preprocessed, only
Keras is needed to use the traces for learning.

Although preprocessed traces are larger than raw ones, the lack of dependence
on external software makes them better suited for shared cluster computing or
for situations where preprocessing is the bottleneck for performance.

# Development

The following is a basic outline of how the code is organized to help
developers get started. The main files are `reader.py`, `generator.py`, and
`lstm.py`.

The reader's job is to handle scanning the filesystem for samples and parsing
PT traces and memory layouts. This is the lowest level code in the project.

The generator's job is to synchronize multiple readers (for performance) and
group their results into sequences (more generally referred to as "samples" in
the ML literature). The generator can be thought of as the glue between the
learner and reader(s).

Finally, the LSTM is the learning model for this system (obviously). `lstm.py`
handles building the model, batching the sequences created by the generator,
training, testing, and evaluation. This is the highest level part of the code
and is where the actual machine learning occurs.

Also worth mentioning is `logger.py`, which provides a unified logging interface
that is multi-process safe. The logger can be configured at runtime to filter
logging to different levels (e.g., only info and above verses debugging).

# Metrics and Visualizations

In addition to the main system code, there are some additional scripts for
calculating and visualizing various metrics:

* `stats.py`: Takes a trace and counts the number of unique targets for each
source and creates a distribution (i.e., number of sources with 1 unique target,
with 2 unique targets, etc.). Currently missing support for preprocesssed
traces.

* `eval.py`: Takes as input the temporary directory created by `lstm.py`
during the evaluation phase and writes to an output directory a bunch of graphs.
Specifically, each trace produces a graph visualizing the predictions within
that trace and a `summary.png` graph is created comparing the traces overall.
