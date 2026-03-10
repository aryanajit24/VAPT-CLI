
from __future__ import annotations

import json
from typing import Any

from vapt import __version__
from vapt.utils.helpers import format_timestamp


class JSONReporter:

    def generate(self, scan_result: dict[str, Any], output_path: str) -> None:
        report = {
            "vapt_cli_version": __version__,
            "generated_at": format_timestamp(),
            "scan_result": scan_result,
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
