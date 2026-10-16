
# LogLens Community — Rule Coverage

## Overview

LogLens Community uses YAML-based detection rules to
identify potentially suspicious activity in normalized
Windows event logs.

The current implementation includes 16 detection rules
across multiple security categories.

## Detection Rule Inventory

| Rule ID | Detection | Event ID | MITRE ATT&CK |
|---|---|---|---|
| LL-AUTH-001 | Failed logon burst | 4625 | T1110 |
| LL-AUTH-002 | Successful logon after failures | 4625, 4624 | T1110 |
| LL-ACCT-001 | New user account created | 4720 | T1136.001 |
| LL-ACCT-002 | User added to security group | 4728, 4732 | T1098 |
| LL-PERSIST-001 | Scheduled task created | 4698 | T1053.005 |
| LL-PERSIST-002 | New service installed | 7045 | T1543.003 |
| LL-EXEC-001 | PowerShell script block logged | 4104 | T1059.001 |
| LL-DEFENSE-001 | Security audit log cleared | 1102 | T1070.001 |
| LL-DEFENSE-002 | Defender protection disabled | 5001 | T1562.001 |
| LL-DEFENSE-003 | Audit policy changed | 4719 | T1562.002 |
| LL-PROC-001 | Encoded PowerShell command | 1 | T1059.001 |
| LL-PROC-005 | Word launches PowerShell | 1 | T1204.002 |
| LL-REG-001 | Registry Run key modified | 13 | T1547.001 |
| LL-DISC-001 | Windows identity discovery | 1 | T1033 |
| LL-NET-001 | Monitored DNS query | 22 | T1071.004 |
| LL-DISC-002 | User account enumeration | 1 | T1087.001 |

## Coverage Summary

- Total YAML rules: 16
- Security categories: 8
- Log sources: Windows Security, Windows System,
  PowerShell Operational, Windows Defender Operational,
  and Sysmon Operational.
- Automated tests: 52 passing as of the latest test run.

## Detection Capabilities

### Authentication
Detects repeated failed logons and successful logons
following a burst of failures.

### Account Management
Detects new user account creation and security group
membership changes.

### Persistence
Detects scheduled task creation, service installation,
and registry Run key modifications.

### Execution and Process Activity
Detects PowerShell script block logging, encoded
PowerShell execution, and Word launching PowerShell.

### Defense Evasion
Detects security log clearing, audit policy changes,
and Microsoft Defender real-time protection being disabled.

### Discovery
Detects identity discovery and user account enumeration.

### Network Activity
Detects DNS queries to a monitored text-sharing domain.

## Testing Status

The automated tests use synthetic Windows events to
verify positive and negative detection behavior.

Real EVTX validation and attack-sample testing remain
pending.

## Known Limitations

- Encoded PowerShell detection currently uses substring
  matching and may miss certain command-line variations.
- Parent-child detection currently uses process fields
  recorded in Sysmon events rather than full process-tree
  reconstruction.
- Some rules identify activities that may also occur
  during legitimate administration.
- A matching event is an investigative lead, not proof
  of malicious activity.

## Next Steps

1. Improve process-tree correlation using ProcessGuid
   and ParentProcessGuid.
2. Validate detection rules against real EVTX logs.
3. Map available attack samples to relevant rules.
4. Verify at least four Atomic Red Team techniques.
5. Prepare the Gate 3 report.



## Gate 3 Validation Results

### Automated Testing

- Automated tests passed: 57
- Detection rules implemented: 16
- Process-tree correlation integrated into the detection engine
- Encoded PowerShell detection enhanced and tested
- CLI analysis and JSON reporting tested

### Real Windows EVTX Validation

| Log Source | Events Analyzed | Findings |
|---|---:|---:|
| Security | 6,328 | 35 |
| Sysmon | 4,575 | 27 |
| System | 1,297 | 15 |
| **Total** | **12,200** | **77** |

Nine detection rules generated findings against the lab logs:

- LL-ACCT-001: 4
- LL-ACCT-002: 13
- LL-AUTH-001: 2
- LL-DEFENSE-003: 7
- LL-PERSIST-001: 9
- LL-DISC-001: 16
- LL-PROC-001: 2
- LL-REG-001: 9
- LL-PERSIST-002: 15

### Attack-Sample Validation

Twenty EVTX attack-sample files were analyzed.

Three samples produced six findings:

| Sample | Rule | Findings |
|---|---|---:|
| LM_Remote_Service02_7045.evtx | LL-PERSIST-002 | 3 |
| Network_Service_Guest_added_to_admins_4732.evtx | LL-ACCT-002 | 2 |
| temp_scheduled_task_4698_4699.evtx | LL-PERSIST-001 | 1 |

The remaining 17 samples produced no findings.

Evidence files:
- reports/security-findings.json
- reports/sysmon-findings.json
- reports/system-findings.json
- reports/attack-sample-validation.csv
- reports/attack-samples/

### MITRE ATT&CK Coverage Evidence

The observed findings include rules mapped to:

| Technique | Description | Evidence |
|---|---|---|
| T1059.001 | PowerShell | Lab Sysmon |
| T1053.005 | Scheduled Task | Lab and attack sample |
| T1547.001 | Registry Run Keys | Lab Sysmon |
| T1543.003 | Windows Service | Lab and attack sample |
| T1098 | Account Manipulation | Lab and attack sample |

These mappings indicate detection coverage for the
associated behaviors. They do not independently confirm
that each finding was caused by an Atomic Red Team test.

### Limitations

- Four distinct Atomic Red Team executions have not yet
  been independently correlated with detection findings.
- The lab Sysmon log contained no Event ID 10 records,
  preventing LSASS-access validation against that file.
- LSASS attack samples were ingested but did not trigger
  an existing detection rule.
- Process-tree correlation requires the relevant parent
  and child process records to be available.
- Detection findings require analyst review; they are not
  automatically confirmed malicious activity.
- Additional tuning and sample coverage are needed to
  reduce false negatives and false positives.

### Gate 3 Status

The detection engine, rule library, automated tests,
CLI reporting, and initial EVTX validation are complete.

Further work is required to establish four independently
confirmed Atomic Red Team technique detections.
