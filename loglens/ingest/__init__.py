from pathlib import Path

from loglens.ingest.evtx import parse_evtx
from loglens.ingest.structured import parse_csv, parse_json

# Windows event IDs listed in Appendix A of the project brief.
SUPPORTED_EVENT_IDS = {
    "Security": {
        4624, 4625, 4634, 4647, 4648, 4672,
        4697, 4698, 4702, 4719, 4720, 4722,
        4724, 4725, 4726, 4728, 4732, 4740,
        4756, 4776, 1102,
    },
    "Microsoft-Windows-Sysmon/Operational": {
        1, 3, 8, 10, 11, 12, 13, 14, 15, 22,
    },
    "System": {
        7045,
    },
}

def is_supported_event(event):
    supported_ids = SUPPORTED_EVENT_IDS.get(event.channel, set())
    return event.event_id in supported_ids

def ingest_file(file_path: Path):
    suffix = file_path.suffix.lower()

    if suffix == ".evtx":
        yield from parse_evtx(file_path)

    elif suffix == ".csv":
        yield from parse_csv(file_path)

    elif suffix == ".json":
        yield from parse_json(file_path)

    else:
        raise ValueError(f"Unsupported file format: {suffix}")