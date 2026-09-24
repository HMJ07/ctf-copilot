
from ctf_copilot.cli import main

NMAP_SAMPLE = """\
Nmap scan report for 10.10.10.5
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
445/tcp  open  microsoft-ds Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
"""


def test_feed_creates_notebook(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.txt"
    scan_file.write_text(NMAP_SAMPLE, encoding="utf-8")

    exit_code = main(["feed", str(scan_file), "--target", "10.10.10.5"])

    assert exit_code == 0
    notebook = tmp_path / ".ctf-copilot" / "10.10.10.5" / "notes.md"
    assert notebook.exists()
    content = notebook.read_text(encoding="utf-8")
    assert "vsftpd 2.3.4" in content
    assert "backdoor" in content.lower()

    captured = capsys.readouterr()
    assert "Ports / services" in captured.out


def test_feed_missing_file_returns_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["feed", "does-not-exist.txt", "--target", "10.10.10.5"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err


def test_suggest_one_off(capsys):
    exit_code = main(["suggest", "--service", "smb", "--version", "Samba 4.3.9"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "enum4linux" in captured.out


def test_notes_command_with_no_notebook_yet(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["notes", "10.10.10.99"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "No notebook yet" in captured.out


def test_feed_no_notebook_flag_skips_write(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.txt"
    scan_file.write_text(NMAP_SAMPLE, encoding="utf-8")

    main(["feed", str(scan_file), "--target", "10.10.10.5", "--no-notebook"])

    notebook = tmp_path / ".ctf-copilot" / "10.10.10.5" / "notes.md"
    assert not notebook.exists()
