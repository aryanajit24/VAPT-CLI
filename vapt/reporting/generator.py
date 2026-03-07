"""Report generation dispatcher."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vapt.reporting.html import HTMLReporter
from vapt.reporting.json_report import JSONReporter
from vapt.reporting.pdf import PDFReporter
from vapt.utils.helpers import format_timestamp
from vapt.utils.validators import sanitize_filename


class ReportGenerator:
    """High-level orchestrator that fans out to format-specific reporters."""

    def __init__(self, output_dir: str | Path = ".") -> None:
        self.output_dir = Path(output_dir)
        # Create the output directory up front so reporters don't have to
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        scan_result: dict[str, Any],
        formats: list[str] | None = None,
        filename_prefix: str | None = None,
    ) -> dict[str, str]:
        """
        Generate reports in all requested formats.

        Parameters
        ----------
        scan_result:     Aggregated scan result dict.
        formats:         List of formats: 'pdf', 'html', 'json'. Defaults to ['html'].
        filename_prefix: Base name for output files. Auto-generated if None.

        Returns
        -------
        Dict mapping format name to the output file path.
        """
        if formats is None:
            formats = ["html"]

        if filename_prefix is None:
            target = scan_result.get("target", "scan")
            ts = format_timestamp().replace(":", "-").replace("+", "").split(".")[0]
            filename_prefix = sanitize_filename(f"{target}_{ts}")

        output_paths: dict[str, str] = {}

        for fmt in formats:
            fmt = fmt.lower()
            if fmt == "html":
                path = self.output_dir / f"{filename_prefix}.html"
                HTMLReporter().generate(scan_result, str(path))
                output_paths["html"] = str(path)
            elif fmt == "pdf":
                path = self.output_dir / f"{filename_prefix}.pdf"
                PDFReporter().generate(scan_result, str(path))
                output_paths["pdf"] = str(path)
            elif fmt == "json":
                path = self.output_dir / f"{filename_prefix}.json"
                JSONReporter().generate(scan_result, str(path))
                output_paths["json"] = str(path)

        return output_paths
