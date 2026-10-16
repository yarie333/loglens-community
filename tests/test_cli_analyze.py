
import json
from datetime import datetime, timezone

from loglens.cli import main
from loglens.schema import NormalizedEvent


def test_analyze_command_creates_json_report(
    tmp_path, monkeypatch, capsys
):
    events = [
        NormalizedEvent(
            timestamp_utc=datetime(
                2026, 10, 15, 12, 0,
                tzinfo=timezone.utc
            ),
            computer="LAB-PC",
            channel="Security",
            event_id=4720,
            target_user="testuser",
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

    input_file = tmp_path / "synthetic.json"
    input_file.write_text("[]", encoding="utf-8")

    output_file = tmp_path / "findings.json"

    def fake_ingest_file(path):
        assert path == input_file
        yield from events

    monkeypatch.setattr(
        "loglens.cli.ingest_file",
        fake_ingest_file
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "loglens",
            "analyze",
            str(input_file),
            "--rules",
            "rules",
            "--output",
            str(output_file),
        ],
    )

    main()

    assert output_file.exists()

    report = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert report["total_events"] == 2
    assert report["rules_loaded"] >= 15

    rule_ids = {
        finding["rule_id"]
        for finding in report["findings"]
    }

    assert "LL-ACCT-001" in rule_ids
    assert "LL-DEFENSE-001" in rule_ids
    assert report["total_findings"] == len(
        report["findings"]
    )

    output = capsys.readouterr().out
    assert "LogLens Analysis Summary" in output
