"""
PDF report writer — for when someone needs to print it.

Renders the HTML template first, then converts it to PDF using
WeasyPrint.  If WeasyPrint isn't installed (it has heavy C deps),
the module falls back gracefully with a helpful error message.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vapt.reporting.html import HTMLReporter
from vapt.utils.helpers import format_timestamp


class PDFReporter:
    """Generate a PDF security report.

    Under the hood this is just the HTML report run through WeasyPrint.
    The CSS in templates/styles.css is designed to work in both browser
    and print contexts.
    """

    def generate(self, scan_result: dict[str, Any], output_path: str) -> None:
        """Render HTML template then convert to PDF."""
        import tempfile

        # First render to a temp HTML file
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp_path = tmp.name

        HTMLReporter().generate(scan_result, tmp_path)

        try:
            from weasyprint import HTML  # type: ignore

            HTML(filename=tmp_path).write_pdf(output_path)
        except ImportError:
            # WeasyPrint not installed — fall back to saving HTML with .pdf extension note
            fallback_path = output_path.replace(".pdf", "_fallback.html")
            Path(fallback_path).write_text(
                Path(tmp_path).read_text(encoding="utf-8"), encoding="utf-8"
            )
            raise RuntimeError(
                f"WeasyPrint not installed. HTML report saved to: {fallback_path}"
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)
