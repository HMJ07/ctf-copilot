import pytest

from ctf_copilot.models import PathFinding, PortFinding
from ctf_copilot.rules.engine import load_default_engine, parse_rules_yaml


@pytest.fixture(scope="module")
def engine():
    return load_default_engine()


def test_default_engine_loads_rules(engine):
    assert engine.rule_count > 10


def test_vsftpd_backdoor_matches(engine):
    finding = PortFinding(port=21, service="ftp", banner="vsftpd 2.3.4")
    suggestions = engine.suggest_for_port(finding, target="10.10.10.5")
    assert any("backdoor" in s.text.lower() for s in suggestions)
    top = max(suggestions, key=lambda s: s.priority)
    assert top.priority == 5


def test_generic_ftp_rule_matches_any_ftp(engine):
    finding = PortFinding(port=21, service="ftp", banner="ProFTPD 1.3.5")
    suggestions = engine.suggest_for_port(finding, target="10.10.10.5")
    assert any(s.rule_id == "ftp-generic" for s in suggestions)
    # The 1.3.3c-specific backdoor rule must NOT fire for a different version.
    assert not any(s.rule_id == "ftp-proftpd-1.3.3c-backdoor" for s in suggestions)


def test_smb_old_samba_matches(engine):
    finding = PortFinding(port=445, service="microsoft-ds", banner="Samba smbd 3.0.20-Debian")
    suggestions = engine.suggest_for_port(finding, target="10.10.10.5")
    assert any(s.rule_id == "smb-old-samba" for s in suggestions)


def test_unmatched_service_returns_empty(engine):
    finding = PortFinding(port=9999, service="totally-unknown-service", banner="")
    suggestions = engine.suggest_for_port(finding)
    assert suggestions == []


def test_command_template_substitutes_target_and_port(engine):
    finding = PortFinding(port=445, service="smb", banner="")
    suggestions = engine.suggest_for_port(finding, target="10.10.10.5")
    enum4linux = next(s for s in suggestions if "enum4linux" in s.command)
    assert "10.10.10.5" in enum4linux.command


def test_path_rule_git_directory(engine):
    finding = PathFinding(path="/.git/config", status=200)
    suggestions = engine.suggest_for_path(finding, target="10.10.10.5")
    assert any(s.rule_id == "git-directory" for s in suggestions)


def test_path_rule_wordpress(engine):
    finding = PathFinding(path="/wp-login.php", status=200)
    suggestions = engine.suggest_for_path(finding, target="10.10.10.5")
    assert any(s.rule_id == "wp-login" for s in suggestions)


def test_suggest_all_dedupes_and_sorts_by_priority(engine):
    ports = [
        PortFinding(port=21, service="ftp", banner="vsftpd 2.3.4"),
        PortFinding(port=445, service="smb", banner=""),
    ]
    paths = [PathFinding(path="/.git/", status=200)]
    suggestions = engine.suggest_all(ports, paths, target="10.10.10.5")
    priorities = [s.priority for s in suggestions]
    assert priorities == sorted(priorities, reverse=True)
    assert priorities[0] == 5  # vsftpd backdoor is the highest-priority hit


def test_suggest_for_service_one_off_lookup(engine):
    suggestions = engine.suggest_for_service(service="smb", version="Samba 4.3.9", target="10.10.10.5")
    assert any(s.rule_id == "smb-generic" for s in suggestions)


def test_custom_rules_yaml_can_be_parsed_independently():
    custom_yaml = """
port_rules:
  - id: custom-test-rule
    services: [foobar]
    suggestions:
      - text: "Custom rule fired for {target}"
        command: "echo {target}:{port}"
        priority: 3
"""
    engine = parse_rules_yaml(custom_yaml)
    finding = PortFinding(port=1234, service="foobar")
    suggestions = engine.suggest_for_port(finding, target="1.2.3.4")
    assert len(suggestions) == 1
    assert suggestions[0].text == "Custom rule fired for 1.2.3.4"
    assert suggestions[0].command == "echo 1.2.3.4:1234"


def test_port_rule_requires_port_match_when_specified():
    custom_yaml = """
port_rules:
  - id: only-port-8080
    services: [http]
    ports: [8080]
    suggestions:
      - text: "hit"
        priority: 1
"""
    engine = parse_rules_yaml(custom_yaml)
    match = engine.suggest_for_port(PortFinding(port=8080, service="http"))
    no_match = engine.suggest_for_port(PortFinding(port=80, service="http"))
    assert len(match) == 1
    assert len(no_match) == 0
