# LogLens Community

LogLens Community is a free, open-source Windows security log analysis application that turns technical security events into plain-English explanations for non-specialists.

Users can export Windows event logs, upload them to LogLens, and receive a security summary, detection findings, recommended next steps, and visualizations to help them understand which activities may need attention.

The application processes logs locally using Python and Streamlit.

## Getting Started

### Installation

Clone the repository and navigate to the project directory.

Install the project and development dependencies:

```powershell
python -m pip install -e ".[dev]"
```

The Streamlit Dashboard and readability testing also require `streamlit`, `pandas`, and `textstat`. Install them if they are not already available:

```powershell
python -m pip install streamlit pandas textstat
```

### Launch the Dashboard

```powershell
python -m streamlit run app.py
```

Open the local Streamlit application in your browser.

The Dashboard accepts Windows event logs in EVTX, CSV, and JSON formats.

### Command-Line Interface

To ingest and normalize Windows events:

```powershell
python -m loglens.cli ingest tests/fixtures/lab/Security.evtx
```

To analyze a log file using the detection rules:

```powershell
python -m loglens.cli analyze tests/fixtures/lab/Security.evtx
```

The ingestion command processes supported log formats and produces normalized event data.

The analysis command applies YAML-based detection rules and generates security findings.

## Key Features

### 1. Windows Event Log Ingestion

LogLens supports three input formats:

- EVTX
- CSV
- JSON

The ingestion code is located in `loglens/ingest/`.

Normalized events follow the schema defined in `loglens/schema.py`.

### 2. Security Detection Engine

LogLens includes 16 YAML-based detection rules covering several types of suspicious Windows activity, including:

- Authentication activity
- Account management
- Persistence
- Execution
- Defense evasion
- Process activity
- Discovery
- Network activity
- Registry modifications

The detection engine analyzes normalized Windows events and produces findings with MITRE ATT&CK mappings, severity levels, explanations, and recommended actions.

Additional detection capabilities include authentication event correlation, encoded PowerShell detection, and process-tree correlation using Sysmon process GUIDs.

Detection rules are stored in the `rules/` directory.

### 3. Streamlit Security Dashboard

The consumer-facing Dashboard allows users to upload and analyze Windows logs without using the command line.

The Dashboard includes:

- Security overview statistics
- Five-line security summary
- Expandable security finding cards
- Findings by severity chart
- Security findings over time chart
- Critical security alerts section
- Investigation priorities explaining what to review first
- Severity filtering and sorting
- Downloadable JSON findings report

Each finding card explains:

1. What happened?
2. Where and when?
3. Could this be normal?
4. What should I do?
5. Technical details

The investigation priority list uses detection-rule severity to suggest a review order. Findings are not proof of an attack, and activities may have legitimate explanations.

### 4. Plain-Language Security Explanations

LogLens is designed for users without specialized cybersecurity knowledge.

Detection findings include explanations of potentially suspicious activity, possible legitimate causes, and practical next steps.

Readability is evaluated using the Flesch–Kincaid Grade Level metric through Python's `textstat` library.

## Testing

The project includes tests for log ingestion, detection functionality, and readability.

Run the full test suite:

```powershell
python -m pytest -v
```

Run ingestion coverage testing:

```powershell
python -m pytest --cov=loglens.ingest --cov-report=term-missing
```

An earlier Week 2 test run completed with 9 passing tests and 96% line coverage for `loglens/ingest/`. This is a historical result, not the current full-suite test count.

### Week 4 Readability Results

The readability test evaluated 35 findings generated from a Windows Security EVTX file.

| Metric | Result |
|---|---|
| Findings tested | 35 |
| Initial average reading grade | 7.99 |
| Final average reading grade | 7.25 |
| Target | Grade 8 or below |
| Result | PASS |

One detection rule, `LL-DEFENSE-003`, initially scored Grade 11.7. Its consumer-facing explanation was simplified, reducing the score to Grade 8.0 without changing the detection logic.

All 35 tested findings displayed reading grades of 8.0 or below.

These results cover the five detection rules that generated findings from the tested Security log. They do not establish readability compliance for all 16 rules.

Run the readability test:

```powershell
python -m pytest tests/test_readability.py -v -s
```

### Dashboard Validation

The Windows Security EVTX file used during Dashboard testing produced the following results:

| Metric | Result |
|---|---|
| Windows events analyzed | 6,328 |
| Security findings generated | 35 |
| Detection rules loaded | 16 |
| Files analyzed | 1 |

The Dashboard's new charts, severity filtering, and investigation priority features require final validation before the Week 4 work is considered fully verified.

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

The benchmark measures the time taken to read and normalize events. Generating the sample file is excluded from the timing.

Memory was measured using Python's `tracemalloc` module, which tracks Python allocations rather than total process memory.

These results apply to the synthetic CSV dataset. EVTX and JSON performance have not yet been benchmarked.

To repeat the benchmark:

```powershell
python -m benchmarks.benchmark_ingest
```

## Project Progress

| Week | Focus | Status |
|---|---|---|
| Week 1 | Windows lab setup, event collection, ground truth, and export documentation | Completed |
| Week 2 | EVTX/CSV/JSON ingestion, normalization, testing, and benchmarking | Completed |
| Week 3 | YAML detection rules, detection engine, event correlation, and JSON findings | Completed |
| Week 4 | Streamlit Dashboard, security visualizations, finding cards, and readability testing | Implemented; final validation pending |

### Pending Work

A usability evaluation involving three nontechnical readers is planned for the following week. Participants will review security finding cards and provide feedback on whether the explanations and recommended actions are understandable.

Additional readability testing is also planned to cover detection rules not exercised by the current Security EVTX sample.

## Documentation

- `docs/field-spec.md` — normalized field definitions and mappings
- `docs/schema.md` — normalized event schema and ingestion behavior
- `docs/export-guide.md` — instructions for exporting Windows event logs
- `docs/week4-evidence/` — Dashboard and readability testing screenshots

## Project Goal

LogLens Community aims to make Windows security information more accessible by translating technical event logs into understandable findings, explaining potential risks, and helping users decide what to investigate next.
