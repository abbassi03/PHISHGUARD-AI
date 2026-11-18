from __future__ import annotations

from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import pandas as pd

from phishguard.features.url_features import normalize_url, registered_domain

LABEL_MAP = {
    "0": 1,  # UCI PhiUSIIL: 0 = phishing; internal positive class = phishing
    "1": 0,  # UCI PhiUSIIL: 1 = legitimate
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "bad": 1,
    "1_phishing": 1,
    "legitimate": 0,
    "legit": 0,
    "benign": 0,
    "safe": 0,
    "0_legitimate": 0,
}


@dataclass
class DatasetAudit:
    input_rows: int
    usable_rows: int
    dropped_missing: int
    dropped_invalid_url: int
    duplicate_urls_removed: int
    conflicting_duplicate_urls: int
    phishing_rows: int
    legitimate_rows: int
    unique_domains: int
    source_columns: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _read_frame(source: str | Path | bytes | BinaryIO) -> pd.DataFrame:
    """Read only URL/label columns to avoid loading unused webpage features into RAM."""
    if isinstance(source, (str, Path)):
        header = pd.read_csv(source, nrows=0).columns.tolist()
        lookup = {str(col).strip().lower(): col for col in header}
        if "url" not in lookup or "label" not in lookup:
            raise ValueError("Dataset must contain columns named URL and label.")
        frame = pd.read_csv(source, usecols=[lookup["url"], lookup["label"]], low_memory=False)
        frame.attrs["source_columns"] = [str(col) for col in header]
        return frame

    if isinstance(source, bytes):
        payload = source
    elif hasattr(source, "getvalue"):
        payload = source.getvalue()
    else:
        if hasattr(source, "seek"):
            source.seek(0)
        payload = source.read()
        if hasattr(source, "seek"):
            source.seek(0)
    header = pd.read_csv(BytesIO(payload), nrows=0).columns.tolist()
    lookup = {str(col).strip().lower(): col for col in header}
    if "url" not in lookup or "label" not in lookup:
        raise ValueError("Dataset must contain columns named URL and label.")
    frame = pd.read_csv(BytesIO(payload), usecols=[lookup["url"], lookup["label"]], low_memory=False)
    frame.attrs["source_columns"] = [str(col) for col in header]
    return frame


def _normalize_label(value: object) -> int:
    text = str(value).strip().lower()
    if text in LABEL_MAP:
        return LABEL_MAP[text]
    # Accept numeric labels only when they are exactly 0 or 1.
    try:
        number = float(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Unsupported label value: {value!r}") from exc
    if number == 0:
        return 1
    if number == 1:
        return 0
    raise ValueError(f"Unsupported label value: {value!r}. Expected 0/1 or phishing/legitimate.")


def prepare_dataset(frame: pd.DataFrame) -> tuple[pd.DataFrame, DatasetAudit]:
    """Keep only URL and label, map label 1 to phishing internally, and audit rows.

    PhiUSIIL source labels are 0=phishing and 1=legitimate. Internal target is
    1=phishing and 0=legitimate so binary metrics have an intuitive positive class.
    """
    if frame.empty:
        raise ValueError("The uploaded dataset is empty.")
    original_columns = list(frame.attrs.get("source_columns", [str(col) for col in frame.columns]))
    lookup = {str(col).strip().lower(): col for col in frame.columns}
    if "url" not in lookup or "label" not in lookup:
        raise ValueError("Dataset must contain columns named URL and label.")
    working = frame[[lookup["url"], lookup["label"]]].copy()
    working.columns = ["url", "source_label"]
    input_rows = len(working)
    missing_mask = working["url"].isna() | working["source_label"].isna()
    dropped_missing = int(missing_mask.sum())
    working = working.loc[~missing_mask].copy()
    working["url"] = working["url"].astype(str).str.strip()
    empty_url_mask = working["url"] == ""
    dropped_missing += int(empty_url_mask.sum())
    working = working.loc[~empty_url_mask].copy()

    try:
        working["target"] = working["source_label"].map(_normalize_label).astype("int8")
    except ValueError as exc:
        raise ValueError(f"Invalid target labels: {exc}") from exc

    # Conflicting labels for an identical URL are an integrity error, not a row to hide.
    label_counts = working.groupby("url", dropna=False)["target"].nunique()
    conflicting_urls = set(label_counts[label_counts > 1].index.tolist())
    if conflicting_urls:
        examples = list(conflicting_urls)[:3]
        raise ValueError(
            f"Found {len(conflicting_urls)} URLs with conflicting labels. Resolve these before training. "
            f"Examples: {examples}"
        )

    duplicate_count = int(working.duplicated(subset=["url"], keep="first").sum())
    working = working.drop_duplicates(subset=["url"], keep="first").copy()

    valid_mask: list[bool] = []
    domains: list[str] = []
    invalid_count = 0
    for url in working["url"].tolist():
        try:
            _, _, hostname = normalize_url(url)
            domains.append(registered_domain(hostname))
            valid_mask.append(True)
        except ValueError:
            domains.append("")
            valid_mask.append(False)
            invalid_count += 1
    working["domain_group"] = domains
    working = working.loc[valid_mask].reset_index(drop=True)
    working = working[["url", "target", "domain_group"]]
    if working["target"].nunique() != 2:
        raise ValueError("After validation, both classes must be present (phishing and legitimate).")
    if working["domain_group"].nunique() < 5:
        raise ValueError("At least five distinct registered domains are required for grouped evaluation.")

    audit = DatasetAudit(
        input_rows=input_rows,
        usable_rows=len(working),
        dropped_missing=dropped_missing,
        dropped_invalid_url=invalid_count,
        duplicate_urls_removed=duplicate_count,
        conflicting_duplicate_urls=0,
        phishing_rows=int((working["target"] == 1).sum()),
        legitimate_rows=int((working["target"] == 0).sum()),
        unique_domains=int(working["domain_group"].nunique()),
        source_columns=original_columns,
    )
    return working, audit


def read_dataset(source: str | Path | bytes | BinaryIO) -> tuple[pd.DataFrame, DatasetAudit]:
    return prepare_dataset(_read_frame(source))
