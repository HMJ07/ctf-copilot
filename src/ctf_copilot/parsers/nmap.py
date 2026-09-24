"""Parser for nmap output: both normal (-oN) and greppable (-oG) formats."""

from __future__ import annotations

import re

from ctf_copilot.models import ParseResult, PortFinding

_NORMAL_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<banner>.*))?$"
)

_HOST_RE = re.compile(r"^Nmap scan report for\s+(?P<host>.+?)\s*$")

_GREP_HOST_RE = re.compile(r"^Host:\s+(?P<host>\S+)\s*(?:\(([^)]*)\))?")
_GREP_PORTS_RE = re.compile(r"Ports:\s*(?P<ports>.+?)(?:\tIgnored State:|$)")


def _looks_like_greppable(text: str) -> bool:
    return "Ports:" in text and re.search(r"^Host:\s", text, re.MULTILINE) is not None


def parse_nmap(text: str) -> ParseResult:
    """Parse nmap output, auto-detecting normal vs. greppable format."""
    if _looks_like_greppable(text):
        return _parse_greppable(text)
    return _parse_normal(text)


def _parse_normal(text: str) -> ParseResult:
    result = ParseResult(tool="nmap")
    current_host = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        host_match = _HOST_RE.match(line.strip())
        if host_match:
            current_host = host_match.group("host")
            if not result.host:
                result.host = current_host
            continue

        port_match = _NORMAL_PORT_RE.match(line.strip())
        if port_match:
            # Every port is recorded regardless of state (open/closed/filtered) so the
            # table view is a complete picture of the scan; the rule engine is
            # responsible for only suggesting next steps on open ports.
            finding = PortFinding(
                port=int(port_match.group("port")),
                protocol=port_match.group("proto"),
                state=port_match.group("state"),
                service=port_match.group("service"),
                banner=(port_match.group("banner") or "").strip(),
                host=current_host,
            )
            result.ports.append(finding)
            result.raw_lines_parsed += 1

    return result


def _parse_greppable(text: str) -> ParseResult:
    result = ParseResult(tool="nmap")
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        host_match = _GREP_HOST_RE.match(line)
        if not host_match:
            continue
        host = host_match.group("host")
        if not result.host:
            result.host = host

        ports_match = _GREP_PORTS_RE.search(line)
        if not ports_match:
            continue

        ports_field = ports_match.group("ports")
        # Entries are comma-separated; each entry is
        # port/state/protocol/owner/service/rpc_info/version/
        for entry in ports_field.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("/")
            if len(parts) < 7:
                continue
            port_str, state, protocol, _owner, service, _rpc, version = parts[:7]
            if not port_str.isdigit():
                continue
            finding = PortFinding(
                port=int(port_str),
                protocol=protocol or "tcp",
                state=state or "unknown",
                service=service or "",
                banner=(version or "").strip(),
                host=host,
            )
            result.ports.append(finding)
            result.raw_lines_parsed += 1

    return result
