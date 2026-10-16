
from pathlib import PureWindowsPath

from loglens.schema import NormalizedEvent


def build_process_tree(
    events: list[NormalizedEvent],
) -> list[dict]:
    """Connect Sysmon processes using their GUIDs."""

    processes = {}

    for event in events:
        if (
            event.channel
            == "Microsoft-Windows-Sysmon/Operational"
            and event.event_id == 1
            and event.process_guid
        ):
            key = (
                event.computer.lower(),
                event.process_guid.lower(),
            )
            processes[key] = event

    relationships = []

    for event in events:
        if (
            event.channel
            != "Microsoft-Windows-Sysmon/Operational"
            or event.event_id != 1
            or not event.parent_guid
        ):
            continue

        parent_key = (
            event.computer.lower(),
            event.parent_guid.lower(),
        )

        parent = processes.get(parent_key)

        if parent is None:
            continue

        relationships.append({
            "computer": event.computer,
            "parent_process": parent.process_name,
            "parent_guid": parent.process_guid,
            "child_process": event.process_name,
            "child_guid": event.process_guid,
            "timestamp": (
                event.timestamp_utc.isoformat()
                if event.timestamp_utc
                else None
            ),
        })

    return relationships


def detect_word_powershell_tree(
    events: list[NormalizedEvent],
) -> list[dict]:
    """Find Word-to-PowerShell relationships."""

    relationships = build_process_tree(events)
    findings = []

    for relationship in relationships:
        parent = relationship["parent_process"]
        child = relationship["child_process"]

        if not parent or not child:
            continue

        parent_name = PureWindowsPath(parent).name.lower()
        child_name = PureWindowsPath(child).name.lower()

        if (
            parent_name == "winword.exe"
            and child_name in ("powershell.exe", "pwsh.exe")
        ):
            findings.append(relationship)

    return findings
