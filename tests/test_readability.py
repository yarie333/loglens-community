
from pathlib import Path

import textstat

from loglens.ingest import ingest_file
from loglens.engine.rule_loader import load_rules
from loglens.engine.detector import analyze_events


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "tests" / "fixtures" / "lab"/ "Security.evtx"
RULES_DIR = PROJECT_ROOT / "rules"

TARGET_GRADE = 8.0


def test_finding_readability():
    # Read our existing Windows Security log
    events = list(ingest_file(LOG_FILE))

    # Load our Week 3 detection rules
    rules = load_rules(RULES_DIR)

    # Generate real findings
    findings = analyze_events(events, rules)

    assert findings, "No findings were generated for readability testing."

    scores = []

    for finding in findings:
        text = finding.get("consumer_text", "").strip()

        if not text:
            continue

        grade = textstat.flesch_kincaid_grade(text)
        scores.append(grade)

        print(
            f"\n{finding.get('rule_id', 'Unknown rule')}"
            f" | Grade: {grade:.1f}"
            f" | Target: {TARGET_GRADE}"
        )

    assert scores, "No consumer explanations were available to test."

    average_grade = sum(scores) / len(scores)

    print("\nREADABILITY SUMMARY")
    print("-------------------")
    print(f"Findings tested: {len(scores)}")
    print(f"Average grade: {average_grade:.2f}")
    print(f"Target grade: {TARGET_GRADE}")

    assert average_grade <= TARGET_GRADE, (
        f"Average reading grade {average_grade:.2f} "
        f"exceeds the Grade {TARGET_GRADE} target."
    )
