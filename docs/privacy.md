
# LogLens Community — Privacy Verification

## Overview

LogLens Community is designed to help users analyze Windows event logs locally.

Windows event logs may contain sensitive information, including usernames, computer names, IP addresses, and process details.

## Local Processing

LogLens processes uploaded security logs using its local Python ingestion and detection engine.

The application does not require a cloud analysis service for its core detection functionality.

## Docker Network Isolation

A separate Docker Compose configuration, docker-compose.offline.yml, uses:

network_mode: "none"

This removes normal network connectivity from the offline analysis container.

## Verification Results

### Network Connectivity Test

An outbound connection to 1.1.1.1 on port 443 was attempted from the isolated container.

Result:

OSError: [Errno 101] Network is unreachable

Status: PASS

### Offline EVTX Analysis

Test file:
Network_Service_Guest_added_to_admins_4732.evtx

Results:

- Events processed: 2
- Detection rules loaded: 16
- Findings generated: 2

Status: PASS

## Privacy Limitations

The standard Streamlit dashboard uses local port 8501 and is not network-isolated in the same way as the offline CLI configuration.

The network isolation test confirms that the isolated container could not establish the tested outbound connection. It does not establish that every component of the application is free from telemetry or external requests.

## Conclusion

Testing confirmed that LogLens Community's core detection engine can analyze Windows event logs inside a network-isolated Docker container.

Additional testing would be required to verify all application components and network behaviors.
