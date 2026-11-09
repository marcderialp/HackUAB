import pytest

from triage.loader import DB_PATH


def pytest_collection_modifyitems(items):
    """Tests marked `db` need the built database; say how to get it instead of failing obscurely."""
    if DB_PATH.exists():
        return
    skip = pytest.mark.skip(reason="run `python -m triage.loader` first")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


def pytest_configure(config):
    config.addinivalue_line("markers", "db: needs the built DuckDB file")
