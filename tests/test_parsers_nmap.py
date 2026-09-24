from ctf_copilot.parsers.nmap import parse_nmap

NORMAL_OUTPUT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for 10.10.10.5
Host is up (0.045s latency).
Not shown: 997 closed tcp ports (reset)

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp  open  microsoft-ds Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""

GREPPABLE_OUTPUT = (
    "Host: 10.10.10.5 ()\tPorts: "
    "21/open/tcp//ftp//vsftpd 2.3.4/, "
    "22/open/tcp//ssh//OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)/, "
    "80/open/tcp//http//Apache httpd 2.2.8 ((Ubuntu) DAV/2)/\t"
    "Ignored State: closed (997)\n"
)


def test_parses_normal_output_host_and_ports():
    result = parse_nmap(NORMAL_OUTPUT)
    assert result.host == "10.10.10.5"
    assert len(result.ports) == 5

    ftp = next(p for p in result.ports if p.port == 21)
    assert ftp.protocol == "tcp"
    assert ftp.state == "open"
    assert ftp.service == "ftp"
    assert "vsftpd 2.3.4" in ftp.banner


def test_parses_normal_output_complex_banner():
    result = parse_nmap(NORMAL_OUTPUT)
    http = next(p for p in result.ports if p.port == 80)
    assert http.service == "http"
    assert "Apache httpd 2.2.8" in http.banner
    assert "DAV/2" in http.banner


def test_parses_greppable_output():
    result = parse_nmap(GREPPABLE_OUTPUT)
    assert result.host == "10.10.10.5"
    assert len(result.ports) == 3

    ssh = next(p for p in result.ports if p.port == 22)
    assert ssh.service == "ssh"
    assert "OpenSSH 4.7p1" in ssh.banner


def test_ignores_closed_ports_state_field():
    result = parse_nmap(NORMAL_OUTPUT)
    assert all(p.state == "open" for p in result.ports)


def test_empty_input_returns_no_ports():
    result = parse_nmap("")
    assert result.ports == []
    assert result.host == ""
