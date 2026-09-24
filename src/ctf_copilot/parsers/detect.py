"""Auto-detection of which parser applies to a blob of pasted/piped tool output."""

from __future__ import annotations

import re

from ctf_copilot.models import ParseResult
from ctf_copilot.parsers.dirscan import parse_dirscan
from ctf_copilot.parsers.nmap import parse_nmap

_PARSERS = {
    "nmap": parse_nmap,
    "dirscan": parse_dirscan,
}

_NMAP_HINTS = (
    re.compile(r"Nmap scan report for", re.IGNORECASE),
    re.compile(r"^Host:\s+\S+.*Ports:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\d+/(tcp|udp)\s+\S+\s+\S+", re.MULTILINE),
    re.compile(r"Starting Nmap", re.IGNORECASE),
)

_DIRSCAN_HINTS = (
    re.compile(r"^/\S*\s+\(Status:\s*\d+\)", re.MULTILINE),  # gobuster
    re.compile(r"^\d{3}\s+\S+\s+\d+l\s+\d+w\s+\d+c\s+\S+", re.MULTILINE),  # feroxbuster
    re.compile(r"^\+\s+\S+\s+\(CODE:\d+\|SIZE:\d+\)", re.MULTILINE),  # dirb
)


def detect_tool(text: str) -> str:
    """Best-effort guess at which tool produced this output. Returns a key into
    the parser registry, or "" if nothing matched confidently."""
    for pattern in _NMAP_HINTS:
        if pattern.search(text):
            return "nmap"
    for pattern in _DIRSCAN_HINTS:
        if pattern.search(text):
            return "dirscan"
    return ""


def parse_with(tool: str, text: str) -> ParseResult:
    """Parse text with an explicitly named parser (nmap|dirscan)."""
    if tool not in _PARSERS:
        raise ValueError(
            f"Unknown parser '{tool}'. Available: {', '.join(sorted(_PARSERS))}"
        )
    return _PARSERS[tool](text)


def detect_and_parse(text: str) -> ParseResult:
    """Detect the tool and parse. Raises ValueError if detection fails."""
    tool = detect_tool(text)
    if not tool:
        raise ValueError(
            "Could not auto-detect the tool that produced this output. "
            "Pass --tool nmap|dirscan explicitly."
        )
    return parse_with(tool, text)
