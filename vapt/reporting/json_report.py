"""
JSON report writer — machine-readable output for CI/CD pipelines.

Produces a structured JSON file that can be fed into SIEM systems,
ticket trackers, or custom dashboards.  Includes a metadata header
with the CLI version and generation timestamp.
"""

from __future__ import annotations

import json
from typing import Any

from vapt import __version__
from vapt.utils.helpers import format_timestamp


class JSONReporter:
    """Serialize scan results to a structured JSON file.

    The output includes a metadata envelope (version, timestamp) around
    the full scan_result dict, so consumers always know what generated it.
    """

    def generate(self, scan_result: dict[str, Any], output_path: str) -> None:
        """Write the scan result to a JSON file."""
        report = {
            "vapt_cli_version": __version__,
            "generated_at": format_timestamp(),
            "scan_result": scan_result,
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
