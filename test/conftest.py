import os
import sys
from pathlib import Path
import importlib.util

import pytest
from sqlalchemy import text
from itsdangerous import URLSafeTimedSerializer


# ----------------------------
# Import server/src/server.py safely
# ----------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_SRC = REPO_ROOT / "server" / "src"

_server_py = SERVER_SRC / "server.py"
spec = importlib.util.spec_from_file_location("tatou_server", _server_py)
tatou_server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(tatou_server)

create_app = tatou_server.create_app


# ----------------------------
# SQLite schema helpers
# ----------------------------

def _init_sqlite_schema(engine):
    """Create minimal schema required for unit tests."""
    with engine.begin() as conn:
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS Documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    path TEXT
                )
            """)
        )
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS Versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    documentid INTEGER,
                    link TEXT,
                    intended_for TEXT,
                    secret TEXT,
                    method TEXT,
                    position TEXT,
                    path TEXT
                )
            """)
        )


# ----------------------------
# Core pytest fixtures
# ----------------------------

@pytest.fixture(scope="session")
def app(tmp_path_factory):
    """
    Creates the Flask app once for the test session using TEST_MODE SQLite.
    """
    os.environ["TEST_MODE"] = "true"
    os.environ["SECRET_KEY"] = "test-secret"

    storage_dir = tmp_path_factory.mktemp("storage")
    os.environ["STORAGE_DIR"] = str(storage_dir)

    app = create_app()

    # Trigger engine creation (healthz calls get_engine -> creates SQLite engine)
    with app.test_client() as c:
        c.get("/healthz")

    # Ensure schema exists once engine exists
    _init_sqlite_schema(app.config["_ENGINE"])
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _clean_db(app):
    """
    Enforces test isolation by clearing SQLite tables between tests.

    - Avoids UNIQUE constraint failures when inserting fixed IDs.
    - Defensive: recreates schema in case a test dropped a table.
    """
    engine = app.config["_ENGINE"]

    # Ensure tables exist before attempting deletes
    _init_sqlite_schema(engine)

    with engine.begin() as conn:
        # Order matters if you later add foreign keys; Versions depends on Documents logically.
        for tbl in ("Versions", "Documents"):
            try:
                conn.execute(text(f"DELETE FROM {tbl}"))
            except Exception:
                # If a test dropped the table, ignore and continue.
                pass

    # Recreate again in case a test DROPPED tables and we ignored deletes
    _init_sqlite_schema(engine)


@pytest.fixture
def auth_header(app):
    """
    Provides a valid Bearer token for endpoints protected by require_auth.
    """
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = s.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
    return {"Authorization": f"Bearer {token}"}


# ----------------------------
# Test helper: insert a document row
# ----------------------------

def insert_document(app, *, doc_id=1, name="doc.pdf", rel_path="files/testuser/doc.pdf"):
    """
    Inserts a Documents row for tests that need an existing document.
    """
    engine = app.config["_ENGINE"]
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO Documents (id, name, path) VALUES (:id, :name, :path)"),
            {"id": doc_id, "name": name, "path": rel_path},
        )


# ----------------------------
# Mock watermarking methods fixture
# ----------------------------

@pytest.fixture
def mock_wm(monkeypatch):
    """
    Forces tests to use custom mock watermarking methods, enabling controlled
    success/failure scenarios for branch coverage of create-watermark and read-watermark.
    """
    import watermarking_utils as WMUtils

    # Ensure test/ directory is importable (so mock_wm_methods.py can be imported)
    TEST_DIR = Path(__file__).resolve().parent
    if str(TEST_DIR) not in sys.path:
        sys.path.insert(0, str(TEST_DIR))

    import mock_wm_methods as mocks

    registry = {
        "mock_ok": mocks.MockOK(),
        "mock_not_applicable": mocks.MockNotApplicable(),
        "mock_apply_raises": mocks.MockApplyRaises(),
        "mock_apply_empty": mocks.MockApplyEmpty(),
        "mock_read_raises": mocks.MockReadRaises(),  # for /api/read-watermark error branch
    }

    # Deterministic lookup for "get_method" used by /api/get-watermarking-methods
    monkeypatch.setattr(WMUtils, "get_method", lambda name: registry[name], raising=True)

    # Ensure /api/get-watermarking-methods returns the mock list (optional but clean)
    monkeypatch.setattr(WMUtils, "METHODS", list(registry.keys()), raising=False)

    # Applicability depends on the selected method (drives create-watermark branches)
    def _is_applicable(method, pdf, position=None):
        return method != "mock_not_applicable"

    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", _is_applicable, raising=True)

    # Apply watermark delegates into our mock object behavior
    def _apply(pdf, secret, key, method, position=None):
        return registry[method].add_watermark(
            pdf=pdf, secret=secret, key=key, position=position
        )

    monkeypatch.setattr(WMUtils, "apply_watermark", _apply, raising=True)

    # Read watermark delegates into our mock object behavior (drives read-watermark branches)
    def _read(method, pdf, key, position=None):
        return registry[method].read_secret(pdf=pdf, key=key, position=position)

    monkeypatch.setattr(WMUtils, "read_watermark", _read, raising=True)

    return registry
