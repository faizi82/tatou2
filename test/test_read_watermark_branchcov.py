"""
Branch coverage tests for /api/read-watermark.

Each test enforces a specific reachable branch in the endpoint:
- missing / invalid document id (from URL / query / JSON)
- missing required fields (method/key)
- database failure when fetching document row
- document not found
- path escape / invalid storage path
- file missing on disk
- watermark read failure (exception)
- successful operation (201)
"""

import os
from pathlib import Path
from sqlalchemy import text


def _insert_doc(app, doc_id: int, name: str, path_value: str):
    """Helper: inserts a Documents row for tests."""
    eng = app.config["_ENGINE"]
    with eng.begin() as conn:
        conn.execute(
            text("INSERT INTO Documents (id, name, path) VALUES (:id, :name, :path)"),
            {"id": doc_id, "name": name, "path": path_value},
        )


def _make_pdf(storage_dir: Path, rel_path: str) -> Path:
    """Helper: writes a small fake PDF to storage."""
    p = storage_dir / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"%PDF-1.4\n%fake\n")
    return p


def test_read_watermark_missing_document_id_400(app, client, auth_header, mock_wm):
    """
    Enforces that if no document id is provided (not in URL, args, or JSON),
    the endpoint returns HTTP 400 for missing/invalid document_id.
    """
    payload = {"method": "mock_ok", "key": "K"}  # method/key present so we reach id parsing
    res = client.post("/api/read-watermark", json=payload, headers=auth_header)
    assert res.status_code == 400
    assert res.get_json()["error"] == "document_id (int) is required"


def test_read_watermark_document_id_from_query_param_201(app, client, auth_header, mock_wm):
    """
    Enforces the branch where document_id is taken from request.args (id/documentid).
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc.pdf")
    _insert_doc(app, 1, "doc.pdf", "files/testuser/doc.pdf")

    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark?id=1", json=payload, headers=auth_header)
    assert res.status_code == 201
    data = res.get_json()
    assert data["documentid"] == 1
    assert data["method"] == "mock_ok"
    assert data["secret"] == "MOCK_SECRET"


def test_read_watermark_document_id_from_json_201(app, client, auth_header, mock_wm):
    """
    Enforces the branch where document_id is taken from JSON body (payload['id']).
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc.pdf")
    _insert_doc(app, 1, "doc.pdf", "files/testuser/doc.pdf")

    payload = {"id": 1, "method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark", json=payload, headers=auth_header)
    assert res.status_code == 201
    data = res.get_json()
    assert data["documentid"] == 1
    assert data["secret"] == "MOCK_SECRET"


def test_read_watermark_missing_method_or_key_400(app, client, auth_header, mock_wm):
    """
    Enforces that missing required fields (method and key) returns HTTP 400.
    """
    # document_id is valid, but key missing
    res = client.post("/api/read-watermark/1", json={"method": "mock_ok"}, headers=auth_header)
    assert res.status_code == 400
    assert res.get_json()["error"] == "method, and key are required"

    # method missing
    res2 = client.post("/api/read-watermark/1", json={"key": "K"}, headers=auth_header)
    assert res2.status_code == 400
    assert res2.get_json()["error"] == "method, and key are required"

    # key not a string
    res3 = client.post("/api/read-watermark/1", json={"method": "mock_ok", "key": 123}, headers=auth_header)
    assert res3.status_code == 400
    assert res3.get_json()["error"] == "method, and key are required"


def test_read_watermark_database_error_503(app, client, auth_header, mock_wm):
    """
    Enforces that a database exception during SELECT returns HTTP 503.
    (We force this by dropping Documents table before hitting the endpoint.)
    """
    eng = app.config["_ENGINE"]
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE Documents"))

    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark/1", json=payload, headers=auth_header)
    assert res.status_code == 503
    assert "database error" in res.get_json()["error"]


def test_read_watermark_document_not_found_404(app, client, auth_header, mock_wm):
    """
    Enforces that a non-existent document id returns HTTP 404.
    """
    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark/999", json=payload, headers=auth_header)
    assert res.status_code == 404
    assert res.get_json()["error"] == "document not found"


def test_read_watermark_path_escape_500(app, client, auth_header, mock_wm):
    """
    Enforces that a DB path escaping STORAGE_DIR is rejected with HTTP 500.
    """
    # absolute path outside storage -> should fail relative_to(storage_root)
    _insert_doc(app, 1, "doc.pdf", "/etc/passwd")

    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark/1", json=payload, headers=auth_header)
    assert res.status_code == 500
    assert res.get_json()["error"] == "document path invalid"


def test_read_watermark_file_missing_410(app, client, auth_header, mock_wm):
    """
    Enforces that if the document exists in DB but the file is missing on disk,
    returns HTTP 410.
    """
    _insert_doc(app, 1, "doc.pdf", "files/testuser/missing.pdf")  # file not created

    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark/1", json=payload, headers=auth_header)
    assert res.status_code == 410
    assert res.get_json()["error"] == "file missing on disk"


def test_read_watermark_read_exception_400(app, client, auth_header, mock_wm):
    """
    Enforces that exceptions raised by WMUtils.read_watermark are returned as HTTP 400.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc.pdf")
    _insert_doc(app, 1, "doc.pdf", "files/testuser/doc.pdf")

    payload = {"method": "mock_read_raises", "key": "K"}
    res = client.post("/api/read-watermark/1", json=payload, headers=auth_header)
    assert res.status_code == 400
    assert "Error when attempting to read watermark" in res.get_json()["error"]


def test_read_watermark_success_201(app, client, auth_header, mock_wm):
    """
    Enforces the full success branch: document exists, file exists, WM read succeeds,
    and returns HTTP 201 with secret.
    """
    storage_dir = Path(os.environ["STORAGE_DIR"])
    _make_pdf(storage_dir, "files/testuser/doc.pdf")
    _insert_doc(app, 1, "doc.pdf", "files/testuser/doc.pdf")

    payload = {"method": "mock_ok", "key": "K"}
    res = client.post("/api/read-watermark/1", json=payload, headers=auth_header)

    assert res.status_code == 201, res.get_json()
    data = res.get_json()
    assert data["documentid"] == 1
    assert data["method"] == "mock_ok"
    assert data["secret"] == "MOCK_SECRET"
