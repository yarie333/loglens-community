from pathlib import Path

import pandas as pd

from loglens.schema import NormalizedEvent

def _clean_value(value):
    if pd.isna(value):
        return None

    return value

def _normalize_row(row: dict) -> NormalizedEvent:
    cleaned = {
        key: _clean_value(value)
        for key, value in row.items()
    }

    return NormalizedEvent(**cleaned)

def parse_csv(file_path: Path):
    dataframe = pd.read_csv(file_path)

    for row in dataframe.to_dict(orient="records"):
        yield _normalize_row(row)

def parse_json(file_path: Path):
    dataframe = pd.read_json(file_path)

    for row in dataframe.to_dict(orient="records"):
        yield _normalize_row(row)       