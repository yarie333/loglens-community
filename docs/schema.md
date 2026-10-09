
# LogLens Community — Normalized Event Schema

## Overview

LogLens Community reads Windows event logs from EVTX, CSV, and JSON files and converts them into a common format.

Windows Security, Sysmon, and System logs contain different types of information. For example, a Security event may contain login details, while a Sysmon event may contain process information. Normalizing these records makes it easier to work with them without having to handle each log format separately.

The normalized event model is defined in `loglens/schema.py` using Pydantic.

## Schema Fields

The table below shows the fields used in the normalized event model.

| Category | Fields | Description |
|---|---|---|
| Event details | `timestamp_utc`, `computer`, `channel`, `event_id`, `record_id` | Basic information about the event |
| Authentication | `user`, `domain`, `logon_type`, `logon_id`, `source_ip`, `source_port` | User and login information |
| Process details | `process_name`, `process_id`, `process_guid`, `command_line`, `image_path`, `hashes` | Information about processes and commands |
| Parent process | `parent_name`, `parent_guid`, `parent_command_line` | Details about the process that started another process |
| System changes | `target_user`, `target_group`, `service_name`, `task_name`, `registry_key`, `dns_query` | Account changes, services, scheduled tasks, registry activity, and DNS queries |
| Original event | `raw_xml` | Original XML retained from EVTX records |

All fields are optional because not every Windows event contains the same information. Missing fields are stored as `None`.

### Data Types

- `timestamp_utc` uses Python's `datetime` type.
- `event_id`, `record_id`, `logon_type`, `source_port`, and `process_id` use integers.
- The remaining fields use strings.

## Ingestion and Normalization

LogLens uses `ingest_file()` in `loglens/ingest/__init__.py` to select the parser based on the file extension.

| File format | Parser |
|---|---|
| `.evtx` | `parse_evtx()` |
| `.csv` | `parse_csv()` |
| `.json` | `parse_json()` |

EVTX files are read using the `evtx` Python library. The parser extracts event metadata and available event fields, then creates a `NormalizedEvent` object. The original XML is also retained in `raw_xml`.

CSV and JSON files are read using pandas. Each record is passed through the Pydantic model to produce the same normalized structure.

Files with unsupported extensions raise a `ValueError`.

## Event Recognition

LogLens uses the event IDs listed in Appendix A of the ChiEAC project brief as its initial v1.0 reference list.

The `is_supported_event()` function checks an event's channel and event ID against this list.

During ingestion, the CLI counts the total number of events and the number of events outside the reference list.

Events outside the list are still included in the normalized output. They are not automatically considered invalid or suspicious.

## Output

The `loglens ingest` command outputs normalized records as JSON.

Event counts are printed separately to standard error (`stderr`) so they do not interfere with the JSON output.

The `raw_xml` field is retained for Learning Mode and should not be displayed in the consumer interface.

## Testing

Ingestion tests are written using pytest and cover CSV, JSON, and EVTX files from the Windows Security, Sysmon, and System logs.

The tests also check unsupported file formats and event recognition.

Current results:
- 9 tests passed
- 96% line coverage for `loglens/ingest/`

The coverage requirement for Week 2 is at least 80%.

To run the tests:

```powershell
python -m pytest --cov=loglens.ingest --cov-report=term-missing
```

## Current Limitations

The event recognition list is limited to the IDs included in Appendix A of the project brief. Other event IDs can still be parsed, but they are counted separately.

The CSV and JSON parsers currently expect records with field names matching the normalized schema. Additional field mappings may be needed for exports that use different column names or structures.

The current tests confirm the expected behavior for selected sample records. They do not yet establish complete field-mapping coverage across all possible Windows events.
