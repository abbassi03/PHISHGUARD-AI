from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold


@dataclass
class DomainSplits:
    train_idx: np.ndarray
    validation_idx: np.ndarray
    test_idx: np.ndarray
    summary: dict


def make_domain_splits(y, groups, random_state: int = 42) -> DomainSplits:
    """Create 60/20/20 train/validation/test folds with registered domains isolated.

    A 5-fold StratifiedGroupKFold is used for the untouched test fold. A second
    grouped 4-fold split on the remaining rows creates validation; the rest is train.
    The method fails closed if a split loses one of the two target classes.
    """
    y_arr = np.asarray(y, dtype=np.int8)
    groups_arr = np.asarray(groups, dtype=str)
    if len(y_arr) != len(groups_arr):
        raise ValueError("Labels and groups must have the same number of rows.")
    if len(np.unique(groups_arr)) < 5:
        raise ValueError("Grouped evaluation needs at least five distinct domains.")
    if len(np.unique(y_arr)) != 2:
        raise ValueError("Both classes must exist before splitting.")

    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    outer_folds = list(outer.split(np.zeros(len(y_arr)), y_arr, groups_arr))
    remaining_idx = outer_folds[1][0]
    test_idx = outer_folds[1][1]

    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=random_state + 1)
    inner_folds = list(
        inner.split(
            np.zeros(len(remaining_idx)),
            y_arr[remaining_idx],
            groups_arr[remaining_idx],
        )
    )
    train_relative, val_relative = inner_folds[0]
    train_idx = remaining_idx[train_relative]
    validation_idx = remaining_idx[val_relative]

    for name, indices in (
        ("train", train_idx),
        ("validation", validation_idx),
        ("test", test_idx),
    ):
        if len(indices) == 0 or len(np.unique(y_arr[indices])) != 2:
            raise ValueError(
                f"The {name} split does not contain both classes. More diverse domains are needed."
            )

    train_groups = set(groups_arr[train_idx])
    val_groups = set(groups_arr[validation_idx])
    test_groups = set(groups_arr[test_idx])
    if train_groups & val_groups or train_groups & test_groups or val_groups & test_groups:
        raise RuntimeError("Domain leakage detected between train, validation and test splits.")

    summary = {
        name: {
            "rows": int(len(indices)),
            "domains": int(len(set(groups_arr[indices]))),
            "phishing": int((y_arr[indices] == 1).sum()),
            "legitimate": int((y_arr[indices] == 0).sum()),
        }
        for name, indices in (
            ("train", train_idx),
            ("validation", validation_idx),
            ("test", test_idx),
        )
    }
    summary["domain_overlap"] = {
        "train_validation": 0,
        "train_test": 0,
        "validation_test": 0,
    }
    return DomainSplits(train_idx, validation_idx, test_idx, summary)
