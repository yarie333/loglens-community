
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class DetectionRule(BaseModel):
    """Validated YAML detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    event_ids: list[int] = Field(min_length=1)
    logic: dict = Field(min_length=1)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    attack: list[str] = Field(min_length=1)
    consumer_text: str = Field(min_length=1)
    false_positive_note: str = Field(min_length=1)
    next_steps: list[str] = Field(min_length=1)
    analyst_notes: str = Field(min_length=1)


def load_rules(directory: str | Path) -> list[DetectionRule]:
    """Load and validate every YAML rule in a directory."""

    directory = Path(directory)

    if not directory.is_dir():
        raise ValueError(f"Rule directory does not exist: {directory}")

    rules = []
    seen_ids = set()

    for file in sorted(
        [*directory.glob("*.yaml"), *directory.glob("*.yml")]
    ):
        try:
            with file.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)

            rule = DetectionRule.model_validate(data)

            if rule.id in seen_ids:
                raise ValueError(f"Duplicate rule ID: {rule.id}")

            seen_ids.add(rule.id)
            rules.append(rule)

        except (yaml.YAMLError, ValidationError, ValueError) as exc:
            raise ValueError(f"Invalid rule in {file}: {exc}") from exc

    if not rules:
        raise ValueError(f"No YAML rules found in {directory}")

    return rules

