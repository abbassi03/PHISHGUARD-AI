from pathlib import Path

from phishguard.config import PROJECT_ROOT, DATA_RAW_DIR, ARTIFACT_DIR


def test_project_paths_resolve_to_repository_root():
    expected_root = Path(__file__).resolve().parents[1]
    assert PROJECT_ROOT == expected_root
    assert DATA_RAW_DIR == expected_root / "data" / "raw"
    assert ARTIFACT_DIR == expected_root / "artifacts"
