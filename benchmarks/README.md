# Standalone benchmarks

From the repo root with a Python environment that has the node dependencies
and Matplotlib:

    py -3.15 -B -m pip install --no-cache-dir --target benchmarks/.deps -r node/requirements.txt matplotlib
    $env:PYTHONPATH = (Resolve-Path benchmarks/.deps).Path
    py -3.15 -B benchmarks/benchmark_runner.py
    py -3.15 -B benchmarks/generate_graphs.py benchmarks/results/<run-directory>

The runner creates fresh node state and records raw samples, summary statistics,
node logs and run metadata in a timestamped folder under results. It does not
start Docker or use the app's databases. Nodes use dynamically assigned
loopback ports. Run on a quiet host for comparable performance numbers.

Consensus is serial HTTP ingress to observed enforcement on all honest peers.
The timer includes the observer's HTTP polling. Successful trials are used for
mean and p95; timeouts remain in the raw data and success denominator. The
serial commit rate uses completed trials divided by the total trial window.
Fault
cases start from fresh state. Conflicts are sampled from observer snapshots,
so zero observed conflicts is not a safety proof. Recovery times local replay
of pre-generated valid certificates; it excludes network transfer and
restart time. Compare runs only with matching timing boundaries and setup.

To run just the microbenchmarks, choose the number of tests with --repeats:

    py -3.15 -B benchmarks/benchmark_runner.py --micro-only --repeats 10

Use the printed run path with generate_graphs.py. The micro chart shows the
total time for each batch. In raw.csv, filter suite to micro, then use trial,
operations and elapsed_ns to calculate your own averages.
