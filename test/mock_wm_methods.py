"""
Custom mock watermarking methods for unit tests.

These mocks reproduce normal behavior and controlled failure scenarios to exercise
branches in the create-watermark endpoint.
"""


class MockOK:
    """Enforces successful watermark creation."""
    name = "mock_ok"

    def add_watermark(self, pdf: str, secret: str, key: str, position=None) -> bytes:
        return b"%PDF-1.4\n%mock-watermarked\n"

    def read_secret(self, pdf: str, key: str, position=None):
        return "MOCK_SECRET"


class MockNotApplicable:
    """Enforces the 'method not applicable' branch."""
    name = "mock_not_applicable"

    def add_watermark(self, pdf: str, secret: str, key: str, position=None) -> bytes:
        return b"%PDF-1.4\n%should-not-run\n"

    def read_secret(self, pdf: str, key: str, position=None):
        return "X"


class MockApplyRaises:
    """Enforces internal watermarking failure (exception during apply)."""
    name = "mock_apply_raises"

    def add_watermark(self, pdf: str, secret: str, key: str, position=None) -> bytes:
        raise RuntimeError("mock apply failed")

    def read_secret(self, pdf: str, key: str, position=None):
        return "X"


class MockApplyEmpty:
    """Enforces internal watermarking failure (empty output)."""
    name = "mock_apply_empty"

    def add_watermark(self, pdf: str, secret: str, key: str, position=None) -> bytes:
        return b""

    def read_secret(self, pdf: str, key: str, position=None):
        return "X"


# test/mock_wm_methods.py

class MockOK:
    """Normal behavior: watermarking produces bytes, reading returns a secret."""
    def add_watermark(self, *, pdf, secret, key, position=None):
        return b"%PDF-1.4\n%watermarked\n"

    def read_secret(self, *, pdf, key, position=None):
        return "MOCK_SECRET"


class MockNotApplicable:
    """Used for create-watermark applicability branch (handled via is_watermarking_applicable)."""
    def add_watermark(self, *, pdf, secret, key, position=None):
        return b"%PDF-1.4\n%watermarked\n"

    def read_secret(self, *, pdf, key, position=None):
        return "MOCK_SECRET"


class MockApplyRaises:
    """create-watermark: apply raises -> 500 branch."""
    def add_watermark(self, *, pdf, secret, key, position=None):
        raise RuntimeError("apply failed intentionally")

    def read_secret(self, *, pdf, key, position=None):
        return "MOCK_SECRET"


class MockApplyEmpty:
    """create-watermark: apply returns empty -> 500 branch."""
    def add_watermark(self, *, pdf, secret, key, position=None):
        return b""

    def read_secret(self, *, pdf, key, position=None):
        return "MOCK_SECRET"


class MockReadRaises:
    """read-watermark: read raises -> 400 branch."""
    def add_watermark(self, *, pdf, secret, key, position=None):
        return b"%PDF-1.4\n%watermarked\n"

    def read_secret(self, *, pdf, key, position=None):
        raise RuntimeError("read failed intentionally")
