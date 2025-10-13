# custom_eof_watermark.py
from typing import Final
from watermarking_method import WatermarkingMethod, PdfSource, load_pdf_bytes

class CustomEOFWatermark(WatermarkingMethod):
    """Byte-level watermark appended after EOF marker."""

    name: Final[str] = "custom-eof"

    def get_usage(self) -> str:
        return "Embed secret bytes after EOF without parsing PDF"

    def is_watermark_applicable(self, pdf: PdfSource, position=None) -> bool:
        # Works for any PDF (even broken ones)
        return True

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position=None) -> bytes:
        data = load_pdf_bytes(pdf)  # <-- call the utility function directly
        marker = b"\n%%CUSTOMEOF_WATERMARK_START\n"
        encoded = secret.encode("utf-8")
        return data + marker + encoded + b"\n%%CUSTOMEOF_WATERMARK_END\n"

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)  # <-- call the utility function directly
        start_marker = b"%%CUSTOMEOF_WATERMARK_START"
        end_marker = b"%%CUSTOMEOF_WATERMARK_END"
        start = data.find(start_marker)
        end = data.find(end_marker)
        if start == -1 or end == -1 or start >= end:
            return ""
        return data[start + len(start_marker):end].strip().decode("utf-8")
