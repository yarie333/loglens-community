# LogLens Community
Loglens Community is a free, open-source desktop application that turns Windows security logs into plain English explations for non-specialists. A user exports the security logs that Windows already keeps, drops them into LogLens, and gets a timeline, a handful of high value alerts, a process tree, a short explanation of what happened and what to do next. Everything runs locally. Nothing is uploaded.



## Getting Started

LogLens Community currently supports reading and normalizing Windows event logs in EVTX, CSV, and JSON formats.

The ingestion code is located in `loglens/ingest/`. Normalized events follow the schema defined in `loglens/schema.py`.

To install the project and development dependencies, run:

    python -m pip install -e ".[dev]"

To ingest a log file, run:

    python -m loglens.cli ingest tests/fixtures/lab/Security.evtx

The command outputs normalized events as JSON and reports the total number of events processed and the number outside the initial supported-event list.

## Testing

The ingestion tests cover EVTX, CSV, and JSON parsing, event recognition, and unsupported file formats.

The latest test run completed with 9 passing tests and 96% line coverage for `loglens/ingest/`.

Run the tests using:

    python -m pytest --cov=loglens.ingest --cov-report=term-missing

## Performance Benchmark

The CSV ingestion benchmark used 100,000 synthetic Windows Security events with Event ID 4625.

| Metric | Result |
|---|---|
| Input format | CSV |
| Events processed | 100,000 |
| Processing time | 1.90 seconds |
| Processing rate | Approximately 52,632 events/second |
| Peak Python-tracked memory | 38.21 MiB |
| Time requirement | Under 60 seconds |
| Result | PASS |

The benchmark measures the time taken to read and normalize the events. Generating the sample file is excluded from the timing.

Memory was measured using Python's `tracemalloc` module, which tracks Python allocations rather than total process memory.

These results apply to the synthetic CSV dataset. EVTX and JSON performance has not yet been benchmarked.

To repeat the benchmark, run:

    python -m benchmarks.benchmark_ingest

## Documentation

- `docs/field-spec.md` — normalized field definitions and mappings
- `docs/schema.md` — normalized event schema and ingestion behavior
- `docs/export-guide.md` — instructions for exporting Windows event logs
