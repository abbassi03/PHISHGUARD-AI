
from pathlib import Path
import pytest

def test_streamlit_home_page_smoke():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    project_root = Path(__file__).resolve().parents[1]
    app_file = project_root / "app.py"

    assert app_file.is_file(), f"Streamlit app not found: {app_file}"

    app = AppTest.from_file(str(app_file)).run(timeout=30)

    assert not app.exception
