from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Optional, Final

import hashlib

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    WatermarkingError,
)

# we will use pypdf (or PyPDF2 fallback) to manipulate the PDF
try:
    from pypdf import PdfReader, PdfWriter  # type: ignore
except Exception:  # pragma: no cover
    from PyPDF2 import PdfReader, PdfWriter  # type: ignore


META_KEY: Final[str] = "/WatermarkSecret"


@dataclass
class HiddenTextWatermark(WatermarkingMethod):
    """
    Watermarking method that hides the secret in the PDF metadata.

    The secret is stored as:
        "<secret>|<sha256(key || secret)>"
    under the metadata key /WatermarkSecret.

    This is invisible in normal viewing but easy for us to read back
    via the API. Stronger than a simple EOF-append.
    """

    name: str = "hidden_text"
    description: str = "Embed the secret in PDF metadata as hidden text"

    def get_usage(self) -> str:
        return (
            "Hidden text watermark in PDF metadata. "
            "Use method='hidden_text'. The 'key' is a string known to you, "
            "and 'secret' is what identifies the recipient or session."
        )

    # ------------- required by WatermarkingMethod ABC -------------

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        """
        Method is applicable if the PDF can be opened by pypdf/PyPDF2.
        """
        try:
            data = load_pdf_bytes(pdf)
            # quick sanity: must look like a PDF
            if not data.lstrip().startswith(b"%PDF"):
                return False
            # try opening
            PdfReader(BytesIO(data))
            return True
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """
        Insert a hidden watermark into the PDF's metadata.

        We encode the secret + a MAC so we can verify the key at read-time.
        """
        if not secret:
            raise ValueError("Secret must be a non-empty string")

        data = load_pdf_bytes(pdf)

        try:
            reader = PdfReader(BytesIO(data))
        except Exception as exc:  # pragma: no cover
            raise WatermarkingError(f"Failed to open PDF: {exc}") from exc

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # copy existing metadata and add our hidden field
        meta = dict(reader.metadata or {})
        payload = self._encode_payload(secret, key)
        meta[META_KEY] = payload
        writer.add_metadata(meta)

        out = BytesIO()
        writer.write(out)
        return out.getvalue()

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
        position: Optional[str] = None,
    ) -> str:
        """
        Given a watermarked PDF (bytes or path) and the key, recover the secret.

        Returns the secret string or "" if not present/invalid.
        """
        data = load_pdf_bytes(pdf)

        try:
            reader = PdfReader(BytesIO(data))
        except Exception as exc:  # pragma: no cover
            raise WatermarkingError(f"Failed to open PDF for reading: {exc}") from exc

        info = reader.metadata or {}
        payload = info.get(META_KEY)
        if not payload:
            return ""

        secret = self._decode_payload(str(payload), key)
        return secret or ""

    # ------------- helpers -------------

    def _encode_payload(self, secret: str, key: str) -> str:
        sec_bytes = secret.encode("utf-8")
        key_bytes = key.encode("utf-8")
        mac = hashlib.sha256(key_bytes + sec_bytes).hexdigest()
        return f"{secret}|{mac}"

    def _decode_payload(self, payload: str, key: str) -> Optional[str]:
        try:
            secret, mac = payload.split("|", 1)
        except ValueError:
            return None

        sec_bytes = secret.encode("utf-8")
        key_bytes = key.encode("utf-8")
        expected = hashlib.sha256(key_bytes + sec_bytes).hexdigest()
        if mac != expected:
            return None
        return secret
