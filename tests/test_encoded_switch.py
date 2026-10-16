
from loglens.engine.detector import (
    has_encoded_powershell_switch,
)


def test_encoded_switch_variations():
    assert has_encoded_powershell_switch(
        "powershell.exe -EncodedCommand SQBFAFgA"
    )
    assert has_encoded_powershell_switch(
        "powershell.exe -enc SQBFAFgA"
    )
    assert has_encoded_powershell_switch(
        "powershell.exe -e SQBFAFgA"
    )
    assert has_encoded_powershell_switch(
        "powershell.exe -EnCoDeDcOmMaNd SQBFAFgA"
    )


def test_encoded_switch_false_positives():
    assert not has_encoded_powershell_switch(
        "powershell.exe -ExecutionPolicy Bypass"
    )
    assert not has_encoded_powershell_switch(
        "powershell.exe -NoProfile"
    )
    assert not has_encoded_powershell_switch(
        "powershell.exe Write-Output 'hello'"
    )
