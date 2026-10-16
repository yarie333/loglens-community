
import pytest

from loglens.engine.rule_loader import load_rules


def test_load_valid_rules():
    rules = load_rules("rules")

    rule_ids = [rule.id for rule in rules]

    assert "LL-AUTH-001" in rule_ids
    assert "LL-AUTH-002" in rule_ids


def test_reject_missing_required_fields(tmp_path):
    rule_file = tmp_path / "invalid.yaml"

    rule_file.write_text(
        "id: LL-TEST-001\ntitle: Incomplete rule\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_reject_duplicate_rule_ids(tmp_path):
    valid_rule = """
id: LL-TEST-001
title: Test rule
channel: Security
event_ids: [4625]
logic:
  threshold: 10
severity: medium
attack: [T1110]
consumer_text: Test description
false_positive_note: Test false positive
next_steps:
  - Investigate the activity
analyst_notes: Test analyst notes
"""

    (tmp_path / "rule1.yaml").write_text(
        valid_rule, encoding="utf-8"
    )
    (tmp_path / "rule2.yaml").write_text(
        valid_rule, encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Duplicate rule ID"):
        load_rules(tmp_path)
