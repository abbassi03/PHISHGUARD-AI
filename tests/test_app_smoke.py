import pytest


def test_streamlit_home_page_smoke():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file("app.py").run(timeout=30)
    assert not app.exception
