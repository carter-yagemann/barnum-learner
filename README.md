# Overview

This system determines if traces of a target program are anomalous
using a two-layer classification.

In the first layer, a deep learning
model is given nominal traces to learn the normal control-flow of the program.
Its learning task is to, given a sequence of basic blocks, determine what the
next basic block should be. The intuition here is that when the program is
behaving normally, this model should be able to predict the paths well. On the
other hand, if the program starts acting abnormally (potentially due to an
exploit), the model should perform poorly.

This is where the second layer comes in. It calculates the first layer's
performance and chooses thresholds to make a final decision about if a trace
is anomalous.

Additionally, this system can attempt to cluster traces that were found to be
anomalous. First, a trace is analyzed to find patches of high misprediction.
If found, those patches are extracted as a slice that should contain mostly
anomalous activity. The slices are converted into vectors and then clustered
using cosine distance.

# Installation

First, install a backend engine for Keras (e.g., Tensorflow). See the Keras
documentation for more details. Then install the requirements:

    pip install -r requirements.txt

This code also requires a modified version of the program `ptxed`, which can
be found in the `ptxed` directory of this repo. First, you'll need `libxed-dev`.
You can download it from your package manager or compile it from
the [repo](https://github.com/intelxed/xed). After that, build `ptxed`:

    mkdir ptxed/build
    cd ptxed/build
    cmake ..
    # Modify CMakeCache.txt so PTXED:BOOL=ON
    make
    # Add ptxed/build/bin to your PATH

Finally, a Redis database is needed to use `knn.py`. If you are not interested in
clustering, this step can be skipped.  Most GNU/Linux distributions already
have a package. For example, on Debian:

    sudo apt install redis-server

# Usage

See `./lstm.py --help`, `./classifier.py --help`, and `./knn.py --help` for options
and usage.

`lstm.py` is the first layer of the model. It has three phases: training, testing,
and evaluation. Training trains the model on nominal traces and testing reports
how well the model can predict the paths of new unseen nominal traces. Finally,
evaluation records the model's (mis)predictions on unseen nominal *and anomalous*
traces.

`classifier.py` takes the output from the evaluation phase and calculates thresholds
for detecting anomalies. It reports the final results in terms of error rates and
produces a graph for visualization.

`knn.py` also takes the output from the previously mentioned evaluation phase and
clusters anomalies using KNN with cosine distance. Note that the evaluation files you
want to query will need to be in a seperate directory from the files used for training. 

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
significantly improve performance. There's also the `--multi-gpu` option in
`lstm.py` if your system has multiple GPUs.

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
more CPU usage and more dependencies like `ptxed`.

Alternatively, `preprocess.py` can be used to (as the name suggests) read raw
traces and save preprocessed versions to storage. Using the `-p` flag in
`lstm.py` will cause the system to only use samples where a preprocessed
version of the trace is available. Note that the computer performing the
preprocessing will still need `ptxed`, but once preprocessed, only
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
with 2 unique targets, etc.).

* `bloom.py`: Takes a saved sets file and counts the number of cumulatively
unique sequences over all the benign traces. In other words, it counts the number
of unique sequences in the first trace, then the number of unique sequences in
the second trace that are not in the first trace, then the number of unique
sequences in the third trace that is in neither the first or second traces, and
so forth.

* `prob.py`: A simple probabilistic model for comparing the first layer against.

* `syscall.py`: An API based model for comparision that can be used in place of
the first layer. Uses API calls taken from Cuckoo reports.
