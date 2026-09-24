from ctf_copilot.models import ParseResult, PathFinding, PortFinding, Suggestion
from ctf_copilot.notebook import append_session, ensure_notebook, notebook_path, read_notebook


def test_notebook_path_sanitizes_target(tmp_path):
    path = notebook_path("10.10.10.5", base_dir=tmp_path)
    assert path == tmp_path / ".ctf-copilot" / "10.10.10.5" / "notes.md"


def test_notebook_path_sanitizes_weird_characters(tmp_path):
    path = notebook_path("http://weird target!", base_dir=tmp_path)
    assert path.parent.parent == tmp_path / ".ctf-copilot"
    assert "/" not in path.parent.name and " " not in path.parent.name


def test_ensure_notebook_creates_file_with_header(tmp_path):
    path = ensure_notebook("10.10.10.5", base_dir=tmp_path)
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "Recon notebook: 10.10.10.5" in content


def test_ensure_notebook_is_idempotent(tmp_path):
    path1 = ensure_notebook("10.10.10.5", base_dir=tmp_path)
    content_after_first = path1.read_text(encoding="utf-8")
    path2 = ensure_notebook("10.10.10.5", base_dir=tmp_path)
    content_after_second = path2.read_text(encoding="utf-8")
    assert path1 == path2
    assert content_after_first == content_after_second


def test_append_session_writes_ports_and_suggestions(tmp_path):
    result = ParseResult(tool="nmap", host="10.10.10.5")
    result.ports.append(PortFinding(port=21, service="ftp", banner="vsftpd 2.3.4"))
    suggestions = [
        Suggestion(text="Try the backdoor", command="msfconsole ...", priority=5, rule_id="ftp-vsftpd-234-backdoor")
    ]

    path = append_session("10.10.10.5", result, suggestions, source_label="scan.txt", base_dir=tmp_path)
    content = path.read_text(encoding="utf-8")

    assert "### Ports / services" in content
    assert "21/tcp" in content
    assert "vsftpd 2.3.4" in content
    assert "### Suggestions" in content
    assert "Try the backdoor" in content
    assert "msfconsole ..." in content
    assert "scan.txt" in content


def test_append_session_writes_paths(tmp_path):
    result = ParseResult(tool="dirscan")
    result.paths.append(PathFinding(path="/admin", status=301, size=313))

    path = append_session("10.10.10.5", result, [], base_dir=tmp_path)
    content = path.read_text(encoding="utf-8")

    assert "### Discovered paths" in content
    assert "/admin" in content
    assert "301" in content


def test_append_session_accumulates_multiple_sessions(tmp_path):
    result1 = ParseResult(tool="nmap")
    result1.ports.append(PortFinding(port=22, service="ssh"))
    append_session("10.10.10.5", result1, [], base_dir=tmp_path)

    result2 = ParseResult(tool="dirscan")
    result2.paths.append(PathFinding(path="/login", status=200))
    append_session("10.10.10.5", result2, [], base_dir=tmp_path)

    content = read_notebook("10.10.10.5", base_dir=tmp_path)
    assert content.count("## Session:") == 2
    assert "22/tcp" in content
    assert "/login" in content


def test_append_session_handles_no_findings(tmp_path):
    result = ParseResult(tool="nmap")
    path = append_session("10.10.10.5", result, [], base_dir=tmp_path)
    content = path.read_text(encoding="utf-8")
    assert "No structured findings" in content


def test_read_notebook_returns_empty_string_when_missing(tmp_path):
    assert read_notebook("nonexistent-target", base_dir=tmp_path) == ""
