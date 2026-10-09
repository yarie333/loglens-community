from pathlib import Path

import pytest

from loglens.ingest import ingest_file, is_supported_event


FIXTURES = Path("tests/fixtures")

def test_csv_ingestion():
    event = next(ingest_file(FIXTURES / "sample.csv"))

    assert event.channel == "Security"
    assert event.event_id == 4625
    assert event.record_id == 328
    assert event.user == "testuser"
    assert event.source_ip == "192.168.1.10"

def test_json_ingestion():
    event = next(ingest_file(FIXTURES / "sample.json"))

    assert event.channel == "Sysmon"
    assert event.event_id == 1
    assert event.record_id == 329
    assert event.user == "testuser"
    assert event.process_name == "powershell.exe"
    assert event.command_line == "powershell.exe -NoProfile"


def test_security_evtx_ingestion():
    event = next(
        ingest_file(FIXTURES / "lab" / "Security.evtx")
    )

    assert event.channel == "Security"
    assert event.event_id is not None
    assert event.timestamp_utc is not None
    assert event.raw_xml is not None
    assert "<Event" in event.raw_xml


def test_sysmon_evtx_ingestion():
    event = next(
        ingest_file(FIXTURES / "lab" / "Sysmon.evtx")
    )

    assert event.channel is not None
    assert event.event_id is not None
    assert event.timestamp_utc is not None
    assert event.raw_xml is not None


def test_system_evtx_ingestion():
    event = next(
        ingest_file(FIXTURES / "lab" / "System.evtx")
    )

    assert event.channel == "System"
    assert event.event_id is not None
    assert event.timestamp_utc is not None
    assert event.raw_xml is not None   

def test_unsupported_file_format():
    unsupported_file = FIXTURES / "sample.txt"

    with pytest.raises(ValueError, match="Unsupported file format"):
        next(ingest_file(unsupported_file))

def test_supported_event():
    event = next(ingest_file(FIXTURES / "sample.csv"))

    assert is_supported_event(event) is True


def test_unsupported_event():
    event = next(
        ingest_file(FIXTURES / "lab" / "Security.evtx")
    )

    assert event.event_id == 4688
    assert is_supported_event(event) is False