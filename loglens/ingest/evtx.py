import json
from datetime import datetime
from pathlib import Path


from evtx import PyEvtxParser
from loglens.schema import NormalizedEvent


def _event_value(event_data: dict, *names):
    for name in names:
        value = event_data.get(name)
        if value not in (None, ""):
            return value
    return None

def _safe_int(value):
    if value in (None, ""):
        return None

    if isinstance(value, int):
        return value

    try:
        return int(str(value), 0)
    except (ValueError, TypeError):
        return None

def parse_evtx(file_path: Path):        


    parser = PyEvtxParser(str(file_path))
    parser = PyEvtxParser(str(file_path))
    xml_parser = PyEvtxParser(str(file_path))

    for record, xml_record in zip(
        parser.records_json(),
        xml_parser.records()
    ):
       data = json.loads(record["data"])


       system = data["Event"]["System"]
       event_data =data["Event"].get("EventData", {})

    
       timestamp_data = system.get("TimeCreated", {})
       timestamp = timestamp_data.get("#attributes", {}).get("SystemTime")

    if timestamp:
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
    )
       
    event = NormalizedEvent(
        timestamp_utc=timestamp,
        channel=system.get("Channel"),
        computer=system.get("Computer"),
        event_id=_safe_int(system.get("EventID")),
        record_id=_safe_int(system.get("EventRecordID")),
    
      
      
    user=_event_value(event_data, "SubjectUserName", "User"),
    domain=_event_value(
            event_data,
            "SubjectDomainName",
            "TargetDomainName"
        ),
    logon_type=_safe_int(
           _event_value(event_data, "LogonType")
        ),
    logon_id=_event_value(
            event_data,
            "TargetLogonId",
            "SubjectLogonId"
        ),
    source_ip=_event_value(
            event_data,
            "IpAddress",
            "SourceIp"
        ),
    source_port=_safe_int(
           _event_value(
            event_data,
            "IpPort",
            "SourcePort"
        )
      ),

    process_name=_event_value(
            event_data,
            "Image",
            "NewProcessName",
            "ProcessName"
        ),
    process_id=_safe_int(
            _event_value(event_data, "ProcessId", "NewProcessId")
        ),
    process_guid=_event_value(event_data, "ProcessGuid"),
    command_line=_event_value(event_data, "CommandLine"),
    image_path=_event_value(
            event_data,
            "Image",
            "NewProcessName"
        ),
    hashes=_event_value(event_data, "Hashes"),

    parent_name=_event_value(
            event_data,
            "ParentImage",
            "ParentProcessName"
        ),
    parent_guid=_event_value(
            event_data,
            "ParentProcessGuid"
        ),
    parent_command_line=_event_value(
            event_data,
            "ParentCommandLine"
        ),

    target_user=_event_value(
            event_data,
            "TargetUserName"
        ),
    target_group=_event_value(
            event_data,
            "TargetGroupName",
            "MemberName"
        ),
    service_name=_event_value(
            event_data,
            "ServiceName"
        ),
    task_name=_event_value(
            event_data,
            "TaskName"
        ),
    registry_key=_event_value(
            event_data,
            "TargetObject"
        ),
    dns_query=_event_value(
            event_data,
            "QueryName"
        ),

    raw_xml=xml_record.get("data"),
    )
    yield event
