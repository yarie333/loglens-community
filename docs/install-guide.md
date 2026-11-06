
# LogLens Community — Installation Guide

## Overview

LogLens Community is a local-first Windows event log analysis tool. It helps users understand Windows security events and identify potentially suspicious activity.

## Requirements

- Windows 10 or Windows 11
- Docker Desktop with Linux containers enabled
- Docker Compose
- Internet access for the initial Docker image build

## Installation

1. Download or clone the LogLens Community repository.
2. Open the project folder in VS Code or PowerShell.
3. Start Docker Desktop.
4. Build the Docker image:

   docker compose build

5. Start the application:

   docker compose up -d

6. Open the dashboard:

   http://localhost:8501

## Using LogLens

1. Open the LogLens dashboard.
2. Navigate to the log analysis page.
3. Upload a supported EVTX, CSV, or JSON file.
4. Review the detection findings and explanations.
5. Export the findings when needed.

## Offline CLI Analysis

The project includes a network-isolated Docker configuration.

To analyze a sample file without container networking:

docker compose -f docker-compose.yml -f docker-compose.offline.yml run --rm --no-deps -v "${PWD}/tests/fixtures:/app/fixtures:ro" loglens loglens analyze /app/fixtures/attack-samples/Network_Service_Guest_added_to_admins_4732.evtx --rules /app/rules

This command is intended for PowerShell.

## Stopping the Application

docker compose down

## Troubleshooting

If Docker is not running, open Docker Desktop and wait for the engine to start.

If port 8501 is already in use, stop any other Streamlit application using that port.

If the dashboard does not open, check the container logs:

docker compose logs --tail=50
