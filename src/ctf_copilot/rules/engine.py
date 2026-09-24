"""Rule-based suggestion engine.

Rules live in a plain YAML data file (rules/data/rules.yaml) so contributors can
add new coverage without touching any Python. See CONTRIBUTING.md for the schema.
"""

from __future__ import annotations

import importlib.resources
import re
from dataclasses import dataclass, field

import yaml

from ctf_copilot.models import PathFinding, PortFinding, Suggestion

_DEFAULT_RULES_PACKAGE = "ctf_copilot.rules.data"
_DEFAULT_RULES_FILE = "rules.yaml"


@dataclass
class _SuggestionTemplate:
    text: str
    command: str = ""
    priority: int = 1


@dataclass
class _PortRule:
    id: str
    services: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    banner_regex: re.Pattern | None = None
    suggestions: list[_SuggestionTemplate] = field(default_factory=list)

    def matches(self, finding: PortFinding) -> bool:
        if self.services and finding.service.lower() not in self.services:
            return False
        if self.ports and finding.port not in self.ports:
            return False
        if self.banner_regex and not self.banner_regex.search(finding.banner or ""):
            return False
        # A rule must key off at least one of service/port to avoid matching everything.
        if not self.services and not self.ports:
            return False
        return True


@dataclass
class _PathRule:
    id: str
    path_regex: re.Pattern
    suggestions: list[_SuggestionTemplate] = field(default_factory=list)

    def matches(self, finding: PathFinding) -> bool:
        return bool(self.path_regex.search(finding.path))


class RuleEngine:
    """Evaluates parsed findings against the loaded rule set."""

    def __init__(self, port_rules: list[_PortRule], path_rules: list[_PathRule]):
        self._port_rules = port_rules
        self._path_rules = path_rules

    @property
    def rule_count(self) -> int:
        return len(self._port_rules) + len(self._path_rules)

    def suggest_for_port(self, finding: PortFinding, target: str = "") -> list[Suggestion]:
        suggestions: list[Suggestion] = []
        for rule in self._port_rules:
            if rule.matches(finding):
                for tmpl in rule.suggestions:
                    suggestions.append(_render(tmpl, rule.id, target, finding.port))
        return suggestions

    def suggest_for_path(self, finding: PathFinding, target: str = "") -> list[Suggestion]:
        suggestions: list[Suggestion] = []
        for rule in self._path_rules:
            if rule.matches(finding):
                for tmpl in rule.suggestions:
                    suggestions.append(_render(tmpl, rule.id, target, path=finding.path))
        return suggestions

    def suggest_for_service(
        self, service: str, version: str = "", port: int | None = None, target: str = ""
    ) -> list[Suggestion]:
        """One-off lookup (used by `ctfc suggest`) without a full parsed finding."""
        finding = PortFinding(
            port=port or 0,
            service=service,
            banner=version,
        )
        results = []
        for rule in self._port_rules:
            # For one-off lookups we don't require a port match if none was given.
            if rule.services and finding.service.lower() not in rule.services:
                continue
            if not rule.services:
                continue
            if rule.banner_regex and not rule.banner_regex.search(version or ""):
                continue
            for tmpl in rule.suggestions:
                results.append(_render(tmpl, rule.id, target, port or 0))
        return results

    def suggest_all(
        self,
        ports: list[PortFinding],
        paths: list[PathFinding],
        target: str = "",
    ) -> list[Suggestion]:
        suggestions: list[Suggestion] = []
        for port_finding in ports:
            suggestions.extend(self.suggest_for_port(port_finding, target))
        for path_finding in paths:
            suggestions.extend(self.suggest_for_path(path_finding, target))
        return _dedupe_sorted(suggestions)


def _render(
    tmpl: _SuggestionTemplate,
    rule_id: str,
    target: str,
    port: int = 0,
    path: str = "",
) -> Suggestion:
    context = {"target": target or "<target>", "port": port, "path": path}
    text = tmpl.text.format(**context)
    command = tmpl.command.format(**context) if tmpl.command else ""
    return Suggestion(
        text=text,
        command=command,
        priority=tmpl.priority,
        rule_id=rule_id,
        source="rule",
    )


def _dedupe_sorted(suggestions: list[Suggestion]) -> list[Suggestion]:
    seen: dict[str, Suggestion] = {}
    for suggestion in suggestions:
        key = (suggestion.rule_id, suggestion.text, suggestion.command)
        seen[str(key)] = suggestion
    return sorted(seen.values(), key=lambda s: s.priority, reverse=True)


def _compile_regex(pattern: str | None) -> re.Pattern | None:
    if not pattern:
        return None
    return re.compile(pattern, re.IGNORECASE)


def _load_suggestions(raw: list[dict]) -> list[_SuggestionTemplate]:
    return [
        _SuggestionTemplate(
            text=item["text"],
            command=item.get("command", ""),
            priority=int(item.get("priority", 1)),
        )
        for item in raw
    ]


def parse_rules_yaml(text: str) -> RuleEngine:
    data = yaml.safe_load(text) or {}

    port_rules = []
    for raw in data.get("port_rules", []):
        port_rules.append(
            _PortRule(
                id=raw["id"],
                services=[s.lower() for s in raw.get("services", [])],
                ports=list(raw.get("ports", [])),
                banner_regex=_compile_regex(raw.get("banner_regex")),
                suggestions=_load_suggestions(raw.get("suggestions", [])),
            )
        )

    path_rules = []
    for raw in data.get("path_rules", []):
        path_rules.append(
            _PathRule(
                id=raw["id"],
                path_regex=re.compile(raw["path_regex"], re.IGNORECASE),
                suggestions=_load_suggestions(raw.get("suggestions", [])),
            )
        )

    return RuleEngine(port_rules=port_rules, path_rules=path_rules)


def load_default_engine() -> RuleEngine:
    """Load the rule set bundled with the package."""
    resource = importlib.resources.files(_DEFAULT_RULES_PACKAGE) / _DEFAULT_RULES_FILE
    text = resource.read_text(encoding="utf-8")
    return parse_rules_yaml(text)


def load_engine_from_file(path: str) -> RuleEngine:
    """Load a rule set from a custom YAML file (e.g. user-contributed rules)."""
    with open(path, encoding="utf-8") as handle:
        return parse_rules_yaml(handle.read())
