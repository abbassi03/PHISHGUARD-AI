import pandas as pd
import pytest

from phishguard.data.dataset import prepare_dataset, read_dataset
from phishguard.data.splitting import make_domain_splits


def _sample_dataset():
    rows = []
    for domain_index in range(30):
        domain = f"site{domain_index}.example"
        for idx in range(6):
            # Source labels follow UCI convention: 0 phishing, 1 legitimate.
            source_label = 0 if idx % 2 == 0 else 1
            prefix = "secure-login-verify" if source_label == 0 else "public-info"
            rows.append({"URL": f"https://{prefix}-{idx}.{domain}/page/{idx}", "label": source_label})
    return pd.DataFrame(rows)


def test_dataset_preparation_maps_labels_and_groups_domains():
    prepared, audit = prepare_dataset(_sample_dataset())
    assert set(prepared["target"].unique()) == {0, 1}
    assert audit.usable_rows == 180
    assert audit.phishing_rows == 90
    assert audit.legitimate_rows == 90
    assert prepared["domain_group"].nunique() == 30


def test_conflicting_duplicate_labels_fail_closed():
    frame = pd.DataFrame({"URL": ["https://example.com/a", "https://example.com/a"], "label": [0, 1]})
    with pytest.raises(ValueError, match="conflicting labels"):
        prepare_dataset(frame)


def test_grouped_splits_have_no_domain_overlap_and_all_classes():
    prepared, _ = prepare_dataset(_sample_dataset())
    splits = make_domain_splits(prepared.target, prepared.domain_group)
    assert splits.summary["domain_overlap"] == {
        "train_validation": 0,
        "train_test": 0,
        "validation_test": 0,
    }
    for key in ("train", "validation", "test"):
        assert splits.summary[key]["phishing"] > 0
        assert splits.summary[key]["legitimate"] > 0


def test_csv_loader_reads_only_url_and_label_but_retains_source_schema():
    csv_bytes = (
        b"FILENAME,URL,URLLength,Title,label\n"
        b"a,https://good0.example,20,Example,1\n"
        b"b,https://bad0.example/login,28,Login,0\n"
        b"c,https://good1.example,20,Example,1\n"
        b"d,https://bad1.example/login,28,Login,0\n"
        b"e,https://good2.example,20,Example,1\n"
        b"f,https://bad2.example/login,28,Login,0\n"
        b"g,https://good3.example,20,Example,1\n"
        b"h,https://bad3.example/login,28,Login,0\n"
        b"i,https://good4.example,20,Example,1\n"
        b"j,https://bad4.example/login,28,Login,0\n"
    )
    prepared, audit = read_dataset(csv_bytes)
    assert list(prepared.columns) == ["url", "target", "domain_group"]
    assert "Title" in audit.source_columns
    assert audit.usable_rows == 10
