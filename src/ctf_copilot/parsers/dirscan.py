"""Parser for content-discovery tool output: gobuster, feroxbuster, dirb."""

from __future__ import annotations

import re

from ctf_copilot.models import ParseResult, PathFinding

# gobuster dir mode, default output:
#   /admin                (Status: 301) [Size: 313] [--> http://target/admin/]
#   /.git                 (Status: 200) [Size: 45]
_GOBUSTER_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)\s*"
    r"\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redirect>\S+)\s*\])?"
)

# feroxbuster default output:
#   200      GET        3l       10w      154c http://target/index.php
#   301      GET        7l       20w      239c http://target/images => http://target/images/
_FEROX_RE = re.compile(
    r"^(?P<status>\d{3})\s+\S+\s+\d+l\s+\d+w\s+(?P<size>\d+)c\s+"
    r"(?P<url>\S+)(?:\s+=>\s+(?P<redirect>\S+))?"
)

# dirb output:
#   + http://target/admin (CODE:200|SIZE:1234)
_DIRB_RE = re.compile(
    r"^\+\s+(?P<url>\S+)\s+\(CODE:(?P<status>\d+)\|SIZE:(?P<size>\d+)\)"
)


def _path_from_url(url: str) -> str:
    match = re.match(r"^[a-zA-Z][\w+.-]*://[^/]+(?P<path>/.*)?$", url)
    if match and match.group("path"):
        return match.group("path")
    return url


def parse_dirscan(text: str) -> ParseResult:
    """Parse gobuster/feroxbuster/dirb directory-discovery output.

    Auto-detects the tool per line, so mixed/concatenated logs still work.
    """
    result = ParseResult(tool="dirscan")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("="):
            continue

        gobuster_match = _GOBUSTER_RE.match(line)
        if gobuster_match:
            result.paths.append(
                PathFinding(
                    path=gobuster_match.group("path"),
                    status=int(gobuster_match.group("status")),
                    size=int(gobuster_match.group("size")),
                    redirect=gobuster_match.group("redirect") or "",
                )
            )
            result.raw_lines_parsed += 1
            continue

        ferox_match = _FEROX_RE.match(line)
        if ferox_match:
            url = ferox_match.group("url")
            result.paths.append(
                PathFinding(
                    path=_path_from_url(url),
                    status=int(ferox_match.group("status")),
                    size=int(ferox_match.group("size")),
                    url=url,
                    redirect=ferox_match.group("redirect") or "",
                )
            )
            result.raw_lines_parsed += 1
            continue

        dirb_match = _DIRB_RE.match(line)
        if dirb_match:
            url = dirb_match.group("url")
            result.paths.append(
                PathFinding(
                    path=_path_from_url(url),
                    status=int(dirb_match.group("status")),
                    size=int(dirb_match.group("size")),
                    url=url,
                )
            )
            result.raw_lines_parsed += 1
            continue

    return result
