from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
class NormalizedEvent(BaseModel):
    """Common event format used throughout LogLens Community"""
    model_config = ConfigDict(extra="ignore")
    timestamp_utc: Optional[datetime] = None
    computer: Optional[str] = None
    channel: Optional[str] = None
    event_id: Optional[int] = None
    record_id: Optional[int] = None
    user: Optional[str] = None
    domain: Optional[str] = None
    logon_type: Optional[int] = None
    logon_id: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_guid: Optional[str] = None
    command_line: Optional[str] = None
    image_path: Optional[str] = None
    hashes: Optional[str] = None
    parent_name: Optional[str] = None
    parent_guid: Optional[str] = None
    parent_command_line: Optional[str] = None

    target_user: Optional[str] = None
    target_group: Optional[str] = None
    service_name: Optional[str] = None
    task_name: Optional[str] = None
    registry_key: Optional[str] = None
    dns_query: Optional[str] = None

    raw_xml: Optional[str] = None

 