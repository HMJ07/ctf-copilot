"""Per-target session notebook: a growing Markdown recon log.

Notes live at ``.ctf-copilot/<target>/notes.md`` relative to the current
working directory, so each engagement/CTF box gets its own log next to
wherever you happen to be running ctfc from.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ctf_copilot.models import ParseResult, Suggestion

NOTEBOOK_DIR_NAME = ".ctf-copilot"
NOTES_FILENAME = "notes.md"


def _sanitize_target(target: str) -> str:
    """Make a target string safe to use as a directory name."""
    cleaned = re.sub(r"[^\w.\-]", "_", target.strip())
    return cleaned or "unknown-target"


def notebook_path(target: str, base_dir: Path | None = None) -> Path:
    base = base_dir if base_dir is not None else Path.cwd()
    return base / NOTEBOOK_DIR_NAME / _sanitize_target(target) / NOTES_FILENAME


def ensure_notebook(target: str, base_dir: Path | None = None) -> Path:
    """Create the notebook file (with a header) if it doesn't exist yet."""
    path = notebook_path(target, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        header = f"# Recon notebook: {target}\n\n_Created {_now()}_\n"
        path.write_text(header, encoding="utf-8")
    return path


def append_session(
    target: str,
    result: ParseResult,
    suggestions: list[Suggestion],
    source_label: str = "",
    base_dir: Path | None = None,
) -> Path:
    """Append a timestamped section to the target's notebook and return its path."""
    path = ensure_notebook(target, base_dir)

    lines: list[str] = []
    lines.append(f"\n## Session: {_now()}\n")
    if source_label:
        lines.append(f"Source: `{source_label}` (parsed as `{result.tool}`)\n")
    else:
        lines.append(f"Parsed as `{result.tool}`\n")

    if result.ports:
        lines.append("\n### Ports / services\n")
        lines.append("| Port | State | Service | Banner |")
        lines.append("|------|-------|---------|--------|")
        for port_finding in sorted(result.ports, key=lambda p: p.port):
            banner = (port_finding.banner or "").replace("|", "\\|")
            lines.append(
                f"| {port_finding.port}/{port_finding.protocol} | {port_finding.state} "
                f"| {port_finding.service} | {banner} |"
            )

    if result.paths:
        lines.append("\n### Discovered paths\n")
        lines.append("| Path | Status | Size |")
        lines.append("|------|--------|------|")
        for path_finding in result.paths:
            size = path_finding.size if path_finding.size is not None else ""
            lines.append(f"| {path_finding.path} | {path_finding.status} | {size} |")

    if suggestions:
        lines.append("\n### Suggestions\n")
        for suggestion in sorted(suggestions, key=lambda s: s.priority, reverse=True):
            stars = "!" * suggestion.priority
            lines.append(f"- **[{stars}]** {suggestion.text}")
            if suggestion.command:
                lines.append(f"  ```\n  {suggestion.command}\n  ```")

    if not result.ports and not result.paths:
        lines.append("\n_No structured findings extracted from this input._\n")

    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    return path


def read_notebook(target: str, base_dir: Path | None = None) -> str:
    path = notebook_path(target, base_dir)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
