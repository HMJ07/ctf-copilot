"""Shared data structures passed between parsers, the rule engine and the notebook."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortFinding:
    """An open (or otherwise reported) port and whatever was learned about it."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    banner: str = ""  # product + version + extra info, as reported by the scanner
    host: str = ""

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass
class PathFinding:
    """A discovered URL path from a content-discovery tool (gobuster/feroxbuster/dirb)."""

    path: str
    status: int | None = None
    size: int | None = None
    url: str = ""
    redirect: str = ""


@dataclass
class TechFinding:
    """A fingerprinted web technology (e.g. from whatweb/nikto/HTTP headers)."""

    name: str
    version: str = ""
    source: str = ""


@dataclass
class ParseResult:
    """Everything a parser extracted from one chunk of tool output."""

    tool: str
    host: str = ""
    ports: list[PortFinding] = field(default_factory=list)
    paths: list[PathFinding] = field(default_factory=list)
    tech: list[TechFinding] = field(default_factory=list)
    raw_lines_parsed: int = 0


@dataclass
class Suggestion:
    """A concrete next step, ranked by priority (higher = more important)."""

    text: str
    command: str = ""
    priority: int = 1
    rule_id: str = ""
    source: str = "rule"  # "rule" or "llm"
