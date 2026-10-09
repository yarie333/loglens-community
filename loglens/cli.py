import sys
import argparse
from pathlib import Path

from loglens.ingest import ingest_file, is_supported_event

def main():
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Normalize Windows event logs."
    )

    subparsers = parser.add_subparsers(dest="command")

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest and normalize a log file."
    )

    ingest_parser.add_argument(
        "file",
        type=Path,
        help="Path to an EVTX, CSV, or JSON file."
    )
    args = parser.parse_args()

    if args.command == "ingest":
        total_events = 0
        unsupported_events = 0

        for event in ingest_file(args.file):
            total_events += 1

            if not is_supported_event(event):
                unsupported_events += 1

            print(event.model_dump_json())

    print(
        f"Total events: {total_events}",
        file=sys.stderr
    )
    print(
        f"Unsupported events: {unsupported_events}",
        file=sys.stderr
    )  
if __name__ == "__main__":
    main()