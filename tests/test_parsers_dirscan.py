from ctf_copilot.parsers.dirscan import parse_dirscan

GOBUSTER_OUTPUT = """\
===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 301) [Size: 313] [--> http://target/admin/]
/.git                 (Status: 200) [Size: 45]
/index.html           (Status: 200) [Size: 1234]
===============================================================
"""

FEROX_OUTPUT = """\
200      GET       10l       20w      154c http://target/index.php
301      GET        7l       20w      239c http://target/images => http://target/images/
404      GET        1l        5w       20c http://target/nope
"""

DIRB_OUTPUT = """\
+ http://target/admin (CODE:200|SIZE:1234)
+ http://target/backup.zip (CODE:200|SIZE:99999)
"""


def test_parses_gobuster_output():
    result = parse_dirscan(GOBUSTER_OUTPUT)
    assert len(result.paths) == 3
    admin = next(p for p in result.paths if p.path == "/admin")
    assert admin.status == 301
    assert admin.size == 313
    assert admin.redirect == "http://target/admin/"


def test_parses_feroxbuster_output():
    result = parse_dirscan(FEROX_OUTPUT)
    assert len(result.paths) == 3
    images = next(p for p in result.paths if p.path == "/images")
    assert images.status == 301
    assert images.redirect == "http://target/images/"


def test_parses_dirb_output():
    result = parse_dirscan(DIRB_OUTPUT)
    assert len(result.paths) == 2
    backup = next(p for p in result.paths if "backup.zip" in p.path)
    assert backup.status == 200
    assert backup.size == 99999


def test_ignores_separator_lines():
    result = parse_dirscan(GOBUSTER_OUTPUT)
    assert all(p.path.startswith("/") for p in result.paths)
