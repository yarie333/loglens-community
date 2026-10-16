
from collections import defaultdict
from datetime import timedelta

from loglens.schema import NormalizedEvent
from loglens.engine.rule_loader import DetectionRule

from loglens.engine.process_tree import detect_word_powershell_tree

import re


def detect_failed_logon_burst(
    events: list[NormalizedEvent],
    rule: DetectionRule,
) -> list[dict]:
    """Detect repeated failed logins within a time window."""

    if rule.id != "LL-AUTH-001":
        raise ValueError(f"Unsupported rule: {rule.id}")

    threshold = rule.logic["threshold"]
    window = timedelta(minutes=rule.logic["window_minutes"])

    grouped = defaultdict(list)

    for event in events:
        if (
            event.channel == rule.channel
            and event.event_id in rule.event_ids
            and event.timestamp_utc is not None
            and event.target_user
        ):
            grouped[
                (event.computer, event.target_user)
            ].append(event)

    findings = []

    for (computer, user), user_events in grouped.items():
        user_events.sort(
            key=lambda event: event.timestamp_utc
        )

        left = 0

        for right, event in enumerate(user_events):
            while (
                event.timestamp_utc
                - user_events[left].timestamp_utc
                > window
            ):
                left += 1

            count = right - left + 1

            if count == threshold:
                findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "computer": computer,
                    "target_user": user,
                    "event_count": count,
                    "first_seen": (
                        user_events[left]
                        .timestamp_utc.isoformat()
                    ),
                    "last_seen": (
                        event.timestamp_utc.isoformat()
                    ),
                    "attack": rule.attack,
                    "consumer_text": rule.consumer_text,
                    "false_positive_note": (
                        rule.false_positive_note
                    ),
                    "next_steps": rule.next_steps,
                    "analyst_notes": rule.analyst_notes,
                })

    return findings


def detect_success_after_failures(
    events: list[NormalizedEvent],
    rule: DetectionRule,
) -> list[dict]:
    """Detect successful logins following repeated failures."""

    if rule.id != "LL-AUTH-002":
        raise ValueError(f"Unsupported rule: {rule.id}")

    sequence = rule.logic["sequence"]

    threshold = sequence[0]["threshold"]

    failure_window = timedelta(
        minutes=sequence[0]["window_minutes"]
    )

    success_window = timedelta(
        minutes=sequence[1]["within_minutes"]
    )

    grouped = defaultdict(list)

    for event in events:
        if (
            event.channel == rule.channel
            and event.event_id in rule.event_ids
            and event.timestamp_utc is not None
            and event.target_user
            and event.target_user != "-"
        ):
            key = (
                event.computer,
                event.target_user.lower(),
            )
            grouped[key].append(event)

    findings = []

    for (computer, user), account_events in grouped.items():
        account_events.sort(
            key=lambda event: event.timestamp_utc
        )

        failures = []

        for event in account_events:
            if event.event_id == 4625:
                failures.append(event)
                continue

            if event.event_id != 4624:
                continue

            recent_failures = [
                failure
                for failure in failures
                if timedelta(0)
                <= (
                    event.timestamp_utc
                    - failure.timestamp_utc
                )
                <= success_window
            ]

            burst_found = False

            for index in range(len(recent_failures)):
                window_start = (
                    recent_failures[index].timestamp_utc
                )

                burst = [
                    failure
                    for failure in recent_failures[index:]
                    if (
                        failure.timestamp_utc
                        - window_start
                        <= failure_window
                    )
                ]

                if len(burst) >= threshold:
                    burst_found = True
                    break

            if burst_found:
                findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "computer": computer,
                    "target_user": user,
                    "timestamp": (
                        event.timestamp_utc.isoformat()
                    ),
                    "failed_attempts": len(
                        recent_failures
                    ),
                    "attack": rule.attack,
                    "consumer_text": rule.consumer_text,
                    "false_positive_note": (
                        rule.false_positive_note
                    ),
                    "next_steps": rule.next_steps,
                    "analyst_notes": rule.analyst_notes,
                })

    return findings


def has_encoded_powershell_switch(command_line: str | None) -> bool:
    """Identify PowerShell encoded-command switches."""

    if not command_line:
        return False

    pattern = (
        r"(?i)(?<!\S)"
        r"[-/](?:e|en|enc|enco|encod|encode|encoded|"
        r"encodedc|encodedco|encodedcom|encodedcomm|"
        r"encodedcomma|encodedcomman|encodedcommand)"
        r"(?=\s|$|:)"
    )

    return re.search(pattern, command_line) is not None


def detect_simple_rule(
    events: list[NormalizedEvent],
    rule: DetectionRule,
) -> list[dict]:
    """Detect events matching simple YAML rules."""

  
    findings = []

    conditions = rule.logic.get("match", {})
    contains_conditions = rule.logic.get("contains", {})
    any_contains_conditions = rule.logic.get("contains_any", {})

    if not isinstance(conditions, dict):
        raise ValueError(
            f"Invalid match conditions in {rule.id}"
        )

    if not isinstance(contains_conditions, dict):
        raise ValueError(
            f"Invalid contains conditions in {rule.id}"
        )

    if not isinstance(any_contains_conditions, dict):
        raise ValueError(
            f"Invalid contains_any conditions in {rule.id}"
        )


    def field_matches(event, field, expected):
        actual = getattr(event, field, None)

        if actual is None:
            return False

        if field in ("process_name", "parent_name"):
            actual_name = (
                str(actual)
                .replace("/", "\\")
                .split("\\")[-1]
            )

            expected_name = (
                str(expected)
                .replace("/", "\\")
                .split("\\")[-1]
            )

            return (
                actual_name.lower()
                == expected_name.lower()
            )

        return actual == expected

    for event in events:
        if event.channel != rule.channel:
            continue

        if event.event_id not in rule.event_ids:
            continue

        if event.timestamp_utc is None:
            continue

        if not all(
            field_matches(event, field, expected)
            for field, expected in conditions.items()
        ):
            continue

   
        if not all(
            isinstance(getattr(event, field, None), str)
            and str(expected).lower()
            in getattr(event, field).lower()
            for field, expected in contains_conditions.items()
        ):
            continue

        
        if not all(
            isinstance(getattr(event, field, None), str)
            and isinstance(values, list)
            and any(
                str(value).lower()
                in getattr(event, field).lower()
                for value in values
            )
            for field, values in any_contains_conditions.items()
        ):
            continue




        findings.append({
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "computer": event.computer,
            "timestamp": (
                event.timestamp_utc.isoformat()
            ),
            "event_id": event.event_id,
            "target_user": event.target_user,
            "attack": rule.attack,
            "consumer_text": rule.consumer_text,
            "false_positive_note": (
                rule.false_positive_note
            ),
            "next_steps": rule.next_steps,
            "analyst_notes": rule.analyst_notes,
        })

    return findings



def analyze_events(
    events: list[NormalizedEvent],
    rules: list[DetectionRule],
) -> list[dict]:
    """Run all detection rules against normalized events."""

    findings = []

    for rule in rules:
        if rule.id == "LL-AUTH-001":
            rule_findings = detect_failed_logon_burst(
                events, rule
            )

        elif rule.id == "LL-AUTH-002":
            rule_findings = detect_success_after_failures(
                events, rule
            )

        
        elif rule.id == "LL-PROC-001":
            rule_findings = detect_simple_rule(events, rule)

            # Keep only findings with a valid
            # encoded-command switch.
            matching_events = {
                (
                    event.computer,
                    event.timestamp_utc.isoformat(),
                )
                for event in events
                if (
                    event.timestamp_utc is not None
                    and event.channel == rule.channel
                    and event.event_id in rule.event_ids
                    and has_encoded_powershell_switch(
                        event.command_line
                    )
                )
            }

            rule_findings = [
                finding
                for finding in rule_findings
                if (
                    finding["computer"],
                    finding["timestamp"],
                ) in matching_events
            ]

    

        elif rule.id == "LL-PROC-005":
            # Detect Word -> PowerShell using Sysmon
            # process GUID relationships.
            tree_matches = detect_word_powershell_tree(
                events
            )

            rule_findings = []

            for match in tree_matches:
                rule_findings.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "computer": match["computer"],
                    "timestamp": match["timestamp"],
                    "parent_process": match["parent_process"],
                    "parent_guid": match["parent_guid"],
                    "child_process": match["child_process"],
                    "child_guid": match["child_guid"],
                    "attack": rule.attack,
                    "consumer_text": rule.consumer_text,
                    "false_positive_note": (
                        rule.false_positive_note
                    ),
                    "next_steps": rule.next_steps,
                    "analyst_notes": rule.analyst_notes,
                })

        else:
            rule_findings = detect_simple_rule(
                events, rule
            )

        findings.extend(rule_findings)

    return findings
