
from __future__ import annotations

from pathlib import Path
from typing import Any

from vapt.reporting.html import HTMLReporter
from vapt.utils.helpers import format_timestamp


class PDFReporter:

    def generate(self, scan_result: dict[str, Any], output_path: str) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp_path = tmp.name

        HTMLReporter().generate(scan_result, tmp_path)

        try:
            from weasyprint import HTML

            HTML(filename=tmp_path).write_pdf(output_path)
        except ImportError:
            fallback_path = output_path.replace(".pdf", "_fallback.html")
            Path(fallback_path).write_text(
                Path(tmp_path).read_text(encoding="utf-8"), encoding="utf-8"
            )
            raise RuntimeError(
                f"WeasyPrint not installed. HTML report saved to: {fallback_path}"
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)
