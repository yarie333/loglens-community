
from datetime import datetime, timedelta, timezone

from loglens.schema import NormalizedEvent
from loglens.engine.rule_loader import load_rules
from loglens.engine.detector import (
    detect_failed_logon_burst,
    detect_success_after_failures,
    detect_simple_rule,
)

from loglens.engine.detector import (
    detect_failed_logon_burst,
    detect_success_after_failures,
    detect_simple_rule,
    analyze_events,
)

import re

def make_failed_logon(minute):
    return NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0, tzinfo=timezone.utc
        ) + timedelta(minutes=minute),
        computer="LAB-PC",
        channel="Security",
        event_id=4625,
        target_user="testuser",
    )


def test_failed_logon_burst_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-AUTH-001"
    ) 

    events = [
        make_failed_logon(i * 0.4)
        for i in range(10)
    ]

    findings = detect_failed_logon_burst(events, rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-AUTH-001"
    assert findings[0]["event_count"] == 10


def test_failed_logon_burst_false_positive():
    rule = next(r for r in load_rules("rules") if r.id == "LL-AUTH-001")

    events = [
        make_failed_logon(i * 2)
        for i in range(10)
    ]

    findings = detect_failed_logon_burst(events, rule)

    assert findings == []



def make_login_event(minute, event_id, user="testuser"):
    return NormalizedEvent(
        timestamp_utc=(
            datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
            + timedelta(minutes=minute)
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=event_id,
        target_user=user,
    )


def get_auth_002_rule():
    return next(
        rule for rule in load_rules("rules")
        if rule.id == "LL-AUTH-002"
    )


def test_success_after_failures_true_positive():
    rule = get_auth_002_rule()

    # Ten failures within 5 minutes.
    events = [
        make_login_event(i * 0.4, 4625)
        for i in range(10)
    ]

    # Successful login one minute after the final failure.
    events.append(make_login_event(4.6, 4624))

    findings = detect_success_after_failures(events, rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-AUTH-002"
    assert findings[0]["target_user"] == "testuser"


def test_success_after_failures_false_positive():
    rule = get_auth_002_rule()

    # Failed attempts belong to testuser.
    events = [
        make_login_event(i * 0.4, 4625)
        for i in range(10)
    ]

    # Successful login belongs to a different account.
    events.append(
        make_login_event(4.6, 4624, user="anotheruser")
    )

    findings = detect_success_after_failures(events, rule)

    assert findings == []



def test_success_after_failures_outside_window():
    rule = get_auth_002_rule()

    # Ten failed logins within 5 minutes.
    events = [
        make_login_event(i * 0.4, 4625)
        for i in range(10)
    ]

    # Successful login more than 10 minutes
    # after the final failed attempt.
    events.append(
        make_login_event(18, 4624)
    )

    findings = detect_success_after_failures(events, rule)

    assert findings == []


def test_account_creation_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-ACCT-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4720,
        target_user="newuser",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-ACCT-001"
    assert findings[0]["target_user"] == "newuser"


def test_account_creation_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-ACCT-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
        target_user="existinguser",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_group_membership_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-ACCT-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4732,
        target_group="Administrators",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-ACCT-002"


def test_group_membership_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-ACCT-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4720,
        target_user="newuser",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_scheduled_task_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PERSIST-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4698,
        task_name="UnexpectedTask",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PERSIST-001"


def test_scheduled_task_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PERSIST-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
        target_user="testuser",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_service_installation_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PERSIST-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="System",
        event_id=7045,
        service_name="TestService",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PERSIST-002"


def test_service_installation_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PERSIST-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4698,
        task_name="TestTask",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_powershell_execution_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-EXEC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-PowerShell/Operational",
        event_id=4104,
        command_line="Write-Output 'Hello LogLens'",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-EXEC-001"


def test_powershell_execution_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-EXEC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
        target_user="testuser",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_audit_log_cleared_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=1102,
        user="Administrator",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-DEFENSE-001"
    assert findings[0]["severity"] == "high"


def test_audit_log_cleared_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
        target_user="Administrator",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []



def test_defender_disabled_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Windows Defender/Operational",
        event_id=5001,
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-DEFENSE-002"
    assert findings[0]["severity"] == "high"


def test_defender_disabled_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_audit_policy_change_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-003"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4719,
        user="Administrator",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-DEFENSE-003"
    assert findings[0]["severity"] == "medium"


def test_audit_policy_change_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DEFENSE-003"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Security",
        event_id=4624,
        target_user="testuser",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_powershell_process_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-001"


def test_powershell_process_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="notepad.exe",
        command_line="notepad.exe",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []



def test_powershell_process_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-001"


def test_powershell_process_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="notepad.exe",
        command_line="notepad.exe",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []



def test_word_launches_powershell_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-005"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        parent_name=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-005"


def test_word_launches_powershell_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-005"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        parent_name="explorer.exe",
        process_name="powershell.exe",
        command_line="powershell.exe -NoProfile",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_registry_run_key_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-REG-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=13,
        registry_key=(
            r"HKCU\Software\Microsoft\Windows"
            r"\CurrentVersion\Run\Updater"
        ),
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-REG-001"


def test_registry_run_key_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-REG-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=13,
        registry_key=r"HKCU\Software\TestApplication\Settings",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_identity_discovery_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DISC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name=r"C:\Windows\System32\whoami.exe",
        command_line="whoami /all",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-DISC-001"


def test_identity_discovery_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DISC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="notepad.exe",
        command_line="notepad.exe",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_monitored_dns_query_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-NET-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=22,
        dns_query="pastebin.com",
        process_name="chrome.exe",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-NET-001"
    assert findings[0]["severity"] == "low"


def test_monitored_dns_query_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-NET-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=22,
        dns_query="example.com",
        process_name="chrome.exe",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_user_enumeration_true_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DISC-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name=r"C:\Windows\System32\net.exe",
        command_line="net user",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-DISC-002"


def test_user_enumeration_false_positive():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-DISC-002"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="net.exe",
        command_line="net use",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_analyze_events_runs_multiple_rules():
    rules = load_rules("rules")

    events = [
        NormalizedEvent(
            timestamp_utc=datetime(
                2026, 10, 15, 12, 0,
                tzinfo=timezone.utc
            ),
            computer="LAB-PC",
            channel="Security",
            event_id=4720,
            target_user="newuser",
        ),
        NormalizedEvent(
            timestamp_utc=datetime(
                2026, 10, 15, 12, 1,
                tzinfo=timezone.utc
            ),
            computer="LAB-PC",
            channel="Security",
            event_id=1102,
            user="Administrator",
        ),
    ]

    findings = analyze_events(events, rules)

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "LL-ACCT-001" in rule_ids
    assert "LL-DEFENSE-001" in rule_ids


def test_encoded_powershell_command_detected():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-001"


def test_normal_powershell_command_not_detected():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="powershell.exe",
        command_line="powershell.exe Get-Process",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []


def test_abbreviated_encoded_powershell_detected():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-001"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-001"


def test_word_launches_powershell_detected():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-005"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_name=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        process_guid="{CHILD-001}",
        parent_guid="{PARENT-001}",
        command_line="powershell.exe Get-Process",
    )

    findings = detect_simple_rule([event], rule)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LL-PROC-005"


def test_explorer_launches_powershell_not_detected():
    rule = next(
        r for r in load_rules("rules")
        if r.id == "LL-PROC-005"
    )

    event = NormalizedEvent(
        timestamp_utc=datetime(
            2026, 10, 15, 12, 0,
            tzinfo=timezone.utc
        ),
        computer="LAB-PC",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        process_name="powershell.exe",
        parent_name="explorer.exe",
        process_guid="{CHILD-002}",
        parent_guid="{PARENT-002}",
        command_line="powershell.exe Get-Process",
    )

    findings = detect_simple_rule([event], rule)

    assert findings == []
