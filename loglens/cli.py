
import sys
import json
import argparse
from pathlib import Path

from loglens.ingest import ingest_file, is_supported_event
from loglens.engine.rule_loader import load_rules
from loglens.engine.detector import analyze_events


def main():
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Normalize and analyze Windows event logs."
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # Existing ingest command
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest and normalize a log file."
    )

    ingest_parser.add_argument(
        "file",
        type=Path,
        help="Path to an EVTX, CSV, or JSON file."
    )

    # New analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a log file using YAML detection rules."
    )

    analyze_parser.add_argument(
        "file",
        type=Path,
        help="Path to an EVTX, CSV, or JSON file."
    )

    analyze_parser.add_argument(
        "--rules",
        type=Path,
        default=Path("rules"),
        help="Directory containing YAML detection rules."
    )

    analyze_parser.add_argument(
        "--output",
        type=Path,
        default=Path("findings.json"),
        help="Path for the JSON findings report."
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

    elif args.command == "analyze":
        # Step 1: Normalize the events
        events = list(ingest_file(args.file))

        # Step 2: Load the YAML rules
        rules = load_rules(args.rules)

        # Step 3: Run the detection engine
        findings = analyze_events(events, rules)

        # Step 4: Build the JSON report
        report = {
            "input_file": str(args.file),
            "total_events": len(events),
            "rules_loaded": len(rules),
            "total_findings": len(findings),
            "findings": findings,
        }

        # Step 5: Save the report
        args.output.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with args.output.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                report,
                file,
                indent=2,
                default=str
            )

        # Step 6: Display the summary
        print("\nLogLens Analysis Summary")
        print("------------------------")
        print(f"Input file: {args.file}")
        print(f"Total events: {len(events)}")
        print(f"Rules loaded: {len(rules)}")
        print(f"Total findings: {len(findings)}")
        print(f"JSON report: {args.output}")


if __name__ == "__main__":
    main()
