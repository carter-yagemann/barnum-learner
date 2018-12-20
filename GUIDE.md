This guide is intended to give tips and tricks for how to get the best learning results.

1. Your results are only as good as your training data.

Machine learning is very sensitive to data poisoning. If your benign dataset actually
contains attacks, the model is going to learn to ignore these. Consider this before
deciding to make a benign dataset using files scraped from Google's search engine.

Similarly, if your benign dataset does not cover some normal activity, traces
may be wrongly detected as containing anomalies.

2. Is your model converging within the first epoch?

Tracing generates a lot of data. Even with giant models that eat up a GPU's entire
memory, they can still converge before the first epoch completes. The question then
is did you provide too much training data or is the model too small? One trick is to
use the `bloom.py` script included in this repo. It'll show how "novel" each additional
trace is. If the curve levels out, you shouldn't need more traces past that point.
Otherwise, your model is too small.

If your model is too small but you don't have the memory for a bigger one, options are
limited. One possibility is to use the CPU version of tensorflow, which uses the CPU's
RAM instead of the GPU's dedicated RAM. The former is often larger than the latter. The
downside is performance. Another option is trying to make your traces smaller. See the
guide in the Barnum tracing repo for details.

3. Exploits are easier to detect than API abuse.

When a malicious input uses exploits to execute ROP chains that hijack the program's
control flow, Barnum performs excellently. On the other hand, calling an API that
saves and executes an embedded attachment is much harder to detect. The problem
is in the latter case, the program is executing as designed and the API may be used
for both benign and malicious purposes. This makes API abuse more ambiguous than
exploits.

If you're mostly interested in API abuse, Barnum may not be the best system to use.
This is not to say Barnum can't detect API abuse, it's just harder.
Instead, because the program is behaving within its specification, it may
be easier to create tools that detect these API abuses. On the other hand, if a
document uses a malformed image to trigger arbitrary code execution, good luck
writting a tool that detects that and every other undiscovered zero day waiting to
be exploited. This is where Barnum shines.
