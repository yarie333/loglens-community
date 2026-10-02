# LogLens Community Field Specification

## Purpose

LogLens community converts Windows Security, Sysmon Operational, and System log data into a normalized event schema. This field specification defines the fields that LogLens Community reads and uses during analysis.

The normalized schema acts as a contract between log ingestion and the detection engine. Regardless of whether the original log is EVTX, CSV, or JSON, supported event data is normalized into these fields.

## Normalized Event Schema

| Field | Meaning |
|---|---|
| `timestamp_utc` | The date and time when the event occurred, converted to UTC. |
| `computer` | The name of the computer that generated the event. |
| `channel` | Log the event came from such as Security, System, or Sysmon Operational. |
| `event_id` | The Windows or Sysmon Event ID identifying the type of event. |
| `record_id` | The unique record number assigned to the event within its Windows event log. |
| `user` | The user account associated with the event. |
| `domain` | The Windows domain or local computer domain associated with the user account. |
| `logon_type` | The Windows logon type describing how a user logged on, such as interactive, network, or Remote Desktop. |
| `logon_id` | The identifier associated with a particular Windows logon session. |
| `source_ip` | The source IP address associated with the event, when available. |
| `source_port` | The source network port associated with the event, when available. |
| `process_name` | The name of the process associated with the event. |
| `process_id` | The numeric identifier assigned to the process. |
| `process_guid` | The Sysmon globally unique identifier for the process. |
| `command_line` | The command line used to start or execute the process. |
| `image_path` | The filesystem path of the executable associated with the event. |
| `hashes` | Available cryptographic hashes recorded for the process or file. |
| `parent_name` | The name of the parent process that started the process. |
| `parent_guid` | The Sysmon globally unique identifier for the parent process. |
| `parent_command_line` | The command line associated with the parent process. |
| `target_user` | The user account targeted by an account, authentication, or permission-related event. |
| `target_group` | The Windows security group targeted by a group-membership event. |
| `service_name` | The name of a Windows service associated with the event. |
| `task_name` | The name of a Windows scheduled task associated with the event. |
| `registry_key` | The Windows Registry key associated with the event. |
| `dns_query` | The DNS name queried by a process or system. |
| `raw_xml` | The original XML representation of the event, retained only for Learning Mode and never shown in the consumer view. |