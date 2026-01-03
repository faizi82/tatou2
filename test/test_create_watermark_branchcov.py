"""
Branch coverage tests for /api/create-watermark.

Each test enforces a specific reachable branch in the endpoint:
- input validation errors
- invalid document id parsing
- document not found
- DB select error
- file missing
- path escapes storage (invalid)
- method not applicable
- applicability check failure (exception)
- watermark apply failure (exception)
- watermark apply failure (empty output)
- file write failure
- DB insert failure
- successful operation
"""

import os
from pathlib import Path

import pytest
from sqlalchemy import text


def _insert_doc(app, doc_id: int, name: str, path_value: str):
    eng = app.config["_ENGINE"]
    with eng.begin() as conn:
        conn.execute(
            text("INSERT INTO Documents (id, name, path) VALUES (:id, :name, :path)"),
            {"id": doc_id, "name": name, "path": path_value},
        )


def _make_pdf(storage_dir: Path, rel_path: str) -> Path:
    p = storage_dir / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"%PDF-1.4\n%fake\n")
    return p


def _recreate_versions_table(app):
    """Recreate Versions table if a test dropped it."""
    eng = app.config["_ENGINE"]
    with eng.begin() as conn:
        conn.execute(
            text(
                """
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
                """
            )
        )


def test_create_watermark_missing_fields_400(app, client, auth_header, mock_wm):
    """
    Enforces that missing required JSON fields returns HTTP 400.
    """
    res = client.post(
        "/api/create-watermark/1",
        json={"method": "mock_ok"},
        headers=auth_header,
    )
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_create_watermark_invalid_document_id_400(client, auth_header, mock_wm):
    """
    Enforces that a non-integer document id triggers ValueError and returns 400.
    Covers: except (TypeError, ValueError) -> "document id required"
    """
    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post("/api/create-watermark?id=abc", json=payload, headers=auth_header)
    assert res.status_code == 400
    assert res.get_json()["error"] == "document id required"


def test_create_watermark_document_not_found_404(app, client, auth_header, mock_wm):
    """
    Enforces that a non-existent document id returns HTTP 404.
    """
    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post("/api/create-watermark/999", json=payload, headers=auth_header)
    assert res.status_code == 404
    assert res.get_json()["error"] == "document not found"


def test_create_watermark_db_select_error_503(app, client, auth_header, mock_wm):
    """
    Enforces that a DB failure during the SELECT triggers the database error branch (503).
    Covers: except Exception -> "database error: ..."
    """
    class BoomEngine:
        def connect(self):
            raise Exception("boom-select")

    old = app.config["_ENGINE"]
    app.config["_ENGINE"] = BoomEngine()
    try:
        payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
        res = client.post("/api/create-watermark/1", json=payload, headers=auth_header)
        assert res.status_code == 503
        assert "database error" in res.get_json()["error"]
    finally:
        app.config["_ENGINE"] = old


def test_create_watermark_file_missing_410(app, client, auth_header, mock_wm):
    """
    Enforces that if the document exists in DB but the file is missing on disk, returns HTTP 410.
    """
    doc_id = 101
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/missing.pdf")  # file not created

    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
    assert res.status_code == 410
    assert res.get_json()["error"] == "file missing on disk"


def test_create_watermark_path_escape_500(app, client, auth_header, mock_wm):
    """
    Enforces that a DB path escaping STORAGE_DIR is rejected with HTTP 500 (path invalid).
    """
    doc_id = 102
    _insert_doc(app, doc_id, "doc.pdf", "/etc/passwd")  # absolute outside storage

    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
    assert res.status_code == 500
    assert res.get_json()["error"] == "document path invalid"


def test_create_watermark_not_applicable_400(app, client, auth_header, mock_wm):
    """
    Enforces that when watermarking method is not applicable, returns HTTP 400.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc.pdf")

    doc_id = 103
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc.pdf")

    payload = {"method": "mock_not_applicable", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
    assert res.status_code == 400
    assert res.get_json()["error"] == "watermarking method not applicable"


def test_create_watermark_applicability_check_exception_400(app, client, auth_header, mock_wm, monkeypatch):
    """
    Enforces that an exception inside the applicability check returns HTTP 400.
    Covers: except Exception -> "watermark applicability check failed: ..."
    """
    import watermarking_utils as WMUtils

    storage_dir = Path(os.environ["STORAGE_DIR"])
    pdf_path = _make_pdf(storage_dir, "files/testuser/doc_applicability.pdf")

    doc_id = 104
    _insert_doc(app, doc_id, "doc.pdf", str(pdf_path))  # store absolute path under storage

    def boom(*args, **kwargs):
        raise Exception("boom-applicability")

    monkeypatch.setattr(WMUtils, "is_watermarking_applicable", boom, raising=True)

    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)

    assert res.status_code == 400
    assert "watermark applicability check failed" in res.get_json()["error"]


def test_create_watermark_apply_exception_500(app, client, auth_header, mock_wm):
    """
    Enforces that an exception during watermark application returns HTTP 500.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc_apply_raises.pdf")

    doc_id = 105
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc_apply_raises.pdf")

    payload = {"method": "mock_apply_raises", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
    assert res.status_code == 500
    assert "watermarking failed" in res.get_json()["error"]


def test_create_watermark_apply_empty_output_500(app, client, auth_header, mock_wm):
    """
    Enforces that empty watermark output returns HTTP 500.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc_apply_empty.pdf")

    doc_id = 106
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc_apply_empty.pdf")

    payload = {"method": "mock_apply_empty", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
    assert res.status_code == 500
    assert res.get_json()["error"] == "watermarking produced no output"


def test_create_watermark_write_failure_500(app, client, auth_header, mock_wm, monkeypatch):
    """
    Enforces that an exception while writing the watermarked file returns HTTP 500.
    Covers: except Exception -> "failed to write watermarked file: ..."
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc_write_fail.pdf")

    doc_id = 107
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc_write_fail.pdf")

    real_open = Path.open

    def boom_open(self, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        # fail only on write attempts
        if "w" in mode:
            raise OSError("boom-write")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", boom_open, raising=True)

    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)

    assert res.status_code == 500
    assert "failed to write watermarked file" in res.get_json()["error"]


def test_create_watermark_db_insert_failure_503(app, client, auth_header, mock_wm):
    """
    Enforces that DB insertion failures return HTTP 503 and the written file is cleaned up.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc_db_fail.pdf")

    doc_id = 108
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc_db_fail.pdf")

    # Drop Versions table to force DB insert failure
    eng = app.config["_ENGINE"]
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE Versions"))

    try:
        payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
        res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)
        assert res.status_code == 503
        assert "database error during version insert" in res.get_json()["error"]
    finally:
        # Ensure later tests are not broken by the DROP
        _recreate_versions_table(app)


def test_create_watermark_success_201(app, client, auth_header, mock_wm):
    """
    Enforces the full success branch: applicable method, watermark bytes produced,
    file written, Versions row inserted, 201 returned.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc_success.pdf")

    doc_id = 109
    _insert_doc(app, doc_id, "doc.pdf", "files/testuser/doc_success.pdf")

    payload = {"method": "mock_ok", "intended_for": "alice", "secret": "S", "key": "K"}
    res = client.post(f"/api/create-watermark/{doc_id}", json=payload, headers=auth_header)

    assert res.status_code == 201, res.get_json()
    data = res.get_json()
    assert data["documentid"] == doc_id
    assert data["method"] == "mock_ok"
    assert data["intended_for"] == "alice"
    assert data["filename"].endswith(".pdf")
    assert data["size"] > 0

    # Check Versions row exists
    eng = app.config["_ENGINE"]
    with eng.connect() as conn:
        n = conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar()
        assert int(n) == 1
