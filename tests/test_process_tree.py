
from datetime import datetime, timezone

from loglens.schema import NormalizedEvent
from loglens.engine.process_tree import (
    build_process_tree,
    detect_word_powershell_tree,
)


def make_event(process, guid, parent_guid):
    return NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 16, 12, 0,
            tzinfo=timezone.utc,
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name=process,
        process_guid=guid,
        parent_guid=parent_guid,
    )


def test_word_powershell_process_tree():
    events = [
        make_event("WINWORD.EXE", "PARENT-001", "ROOT-001"),
        make_event("powershell.exe", "CHILD-001", "PARENT-001"),
    ]

    relationships = build_process_tree(events)
    findings = detect_word_powershell_tree(events)

    assert len(relationships) == 1
    assert len(findings) == 1
    assert findings[0]["parent_guid"] == "PARENT-001"


def test_unrelated_process_tree():
    events = [
        make_event("explorer.exe", "PARENT-002", "ROOT-002"),
        make_event("powershell.exe", "CHILD-002", "PARENT-002"),
    ]

    findings = detect_word_powershell_tree(events)

    assert findings == []


from loglens.engine.detector import analyze_events
from loglens.engine.rule_loader import load_rules


def test_analyze_events_uses_process_tree():
    events = [
        make_event(
            "WINWORD.EXE",
            "PARENT-100",
            "ROOT-100"
        ),
        make_event(
            "powershell.exe",
            "CHILD-100",
            "PARENT-100"
        ),
    ]

    rules = load_rules("rules")

    findings = analyze_events(events, rules)

    matches = [
        finding
        for finding in findings
        if finding["rule_id"] == "LL-PROC-005"
    ]

    assert len(matches) == 1
    assert matches[0]["parent_guid"] == "PARENT-100"
    assert matches[0]["child_guid"] == "CHILD-100"
