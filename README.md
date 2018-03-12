# Installation

First, install a backend engine for Keras (e.g., Tensorflow). See Keras
documentation for more details. Then, install requirements:

    pip install -r requirements.txt

Additionally, this code requires the program `ptxed`, which is included in
the [libipt](https://github.com/01org/processor-trace) source code repo.
This can either be installed from source or using the following APT repo
maintained by the main author of this project:

    sh -c "$(wget -qO - https://super.gtisc.gatech.edu/libipt.sh)"
    sudo apt-get install ptxed

# Usage

See `./lstm.py --help` for options and usage.

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
