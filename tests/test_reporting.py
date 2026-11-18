import pandas as pd

from phishguard.reporting.export import dataframe_to_csv


def test_csv_export_neutralizes_spreadsheet_formulas():
    frame = pd.DataFrame({"url": ["=HYPERLINK('https://bad.example')", "https://good.example"], "count": [1, 2]})
    exported = dataframe_to_csv(frame).decode("utf-8-sig")
    assert "'=HYPERLINK" in exported
    assert "https://good.example" in exported
