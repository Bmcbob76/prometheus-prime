"""
Reporting engine for PROMETHEUS-PRIME (lab-only)
- Generates Markdown or JSON reports from operation results
- Writes to reports_dir configured in configs/default.yaml
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def render_markdown_report(title: str, summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if "operation" in summary:
        lines.append(f"- Operation: {summary.get('operation')}")
    if "targets" in summary:
        lines.append(f"- Targets: {', '.join(map(str, summary.get('targets', [])))}")
    lines.append("")
    if "findings" in summary:
        lines.append("## Findings")
        findings = summary.get("findings", {})
        for section, content in findings.items():
            lines.append(f"### {section}")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        lines.append(f"- {json.dumps(item, ensure_ascii=False)}")
                    else:
                        lines.append(f"- {item}")
            elif isinstance(content, dict):
                for k, v in content.items():
                    if isinstance(v, (dict, list)):
                        v_str = json.dumps(v, ensure_ascii=False)
                    else:
                        v_str = str(v)
                    lines.append(f"- {k}: {v_str}")
            else:
                lines.append(f"- {content}")
            lines.append("")
    if "notes" in summary:
        lines.append("## Notes")
        notes = summary.get("notes", [])
        for n in notes:
            lines.append(f"- {n}")
    return "\n".join(lines).strip() + "\n"


def write_report(
    reports_dir: str,
    title: str,
    summary: Dict[str, Any],
    format: str = "markdown",
    subfolder: Optional[str] = None
) -> Path:
    """
    Write a report file.
    - format: 'markdown' or 'json'
    - subfolder: optional subdirectory under reports_dir (e.g., 'nmap')
    Returns path to the written file.
    """
    base = Path(reports_dir).resolve()
    if subfolder:
        base = base.joinpath(subfolder)
    _ensure_dir(base)

    ts = _timestamp()
    safe_title = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in title)[:60]
    if format.lower() in ("md", "markdown"):
        outfile = base.joinpath(f"{ts}_{safe_title}.md")
        outfile.write_text(render_markdown_report(title, summary), encoding="utf-8")
    elif format.lower() == "json":
        outfile = base.joinpath(f"{ts}_{safe_title}.json")
        outfile.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    else:
        raise ValueError("Unsupported report format. Use 'markdown' or 'json'.")

    return outfile


__all__ = ["write_report", "render_markdown_report"]
