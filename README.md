# ctf-copilot

[![CI](https://github.com/HMJ07/ctf-copilot/actions/workflows/ci.yml/badge.svg)](https://github.com/HMJ07/ctf-copilot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)
[![PyPI](https://img.shields.io/badge/PyPI-not%20yet%20published-lightgrey)](https://pypi.org/)

A **local-first** CLI copilot for CTF players and pentesters during
recon/enumeration. Feed it the raw output of `nmap`, `gobuster`,
`feroxbuster`, `dirb` (and friends) and it will:

- Parse it into structured findings (open ports, services, versions,
  discovered paths).
- Suggest concrete, ranked next steps — with the **exact command** to run —
  from a built-in, extensible rule set covering common services and
  well-known vulnerable versions.
- Log everything to a running Markdown notebook per target, so your recon
  session builds itself as you go.
- Optionally ask a local (Ollama) or remote (OpenAI-compatible) LLM for extra
  open-ended ideas when the rule engine draws a blank — entirely opt-in.

No account, no telemetry, no network calls unless you explicitly configure an
LLM backend. See [Offline guarantee](#offline-guarantee).

> **Disclaimer:** ctf-copilot is intended for CTF competitions and
> **authorized** security testing only. Only point it at systems you own or
> have explicit written permission to test. The authors take no
> responsibility for misuse.

## Demo

```console
$ nmap -sV -oN scan.txt 10.10.10.5
$ ctfc feed scan.txt --target 10.10.10.5

                              Ports / services
┏━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port    ┃ State ┃ Service     ┃ Banner                                 ┃
┡━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 21/tcp  │ open  │ ftp         │ vsftpd 2.3.4                           │
│ 22/tcp  │ open  │ ssh         │ OpenSSH 4.7p1 Debian 8ubuntu1           │
│ 80/tcp  │ open  │ http        │ Apache httpd 2.2.8 ((Ubuntu) DAV/2)     │
│ 445/tcp │ open  │ microsoft-ds│ Samba smbd 3.0.20-Debian                │
└─────────┴───────┴─────────────┴─────────────────────────────────────────┘
╭─ [*****] vsftpd 2.3.4 is vulnerable to the well-known backdoor ─────────╮
│ $ msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; ...'      │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ [****] Old Samba version detected — check CVE-2017-7494 ... ──────────╮
│ $ msfconsole -q -x 'search samba; use exploit/multi/samba/...'         │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ [**] HTTP is open. Fingerprint the stack and start content discovery. ╮
│ $ whatweb http://10.10.10.5:80/ && gobuster dir -u http://10.10.10.5.. │
╰──────────────────────────────────────────────────────────────────────────╯

Logged to .ctf-copilot/10.10.10.5/notes.md

$ gobuster dir -u http://10.10.10.5 -w common.txt -o dir.txt
$ ctfc feed dir.txt --target 10.10.10.5

$ ctfc notes 10.10.10.5      # reopen the running recon log at any time
```

Piping straight from the tool works too:

```console
$ gobuster dir -u http://10.10.10.5 -w wordlist.txt | ctfc feed - --target 10.10.10.5
```

One-off lookups without any scan file:

```console
$ ctfc suggest --service smb --version "Samba 4.3.9"
```

## Install

```bash
pip install -e .          # from a cloned checkout, editable install
# or, once published:
pip install ctf-copilot
```

This installs two equivalent console commands: `ctfc` and `ctf-copilot`.

Requires **Python 3.9+**. Runs on Linux, macOS and Windows.

Optional LLM support:

```bash
pip install "ctf-copilot[llm]"
```

## Usage

```text
ctfc feed <file|-> --target <host> [--tool auto|nmap|dirscan] [--llm] [--no-notebook]
ctfc notes <target> [--path]
ctfc suggest --service <name> [--version <banner>] [--port <n>] [--target <host>]
```

- `ctfc feed` — parse a file (or `-` for stdin) and print findings +
  suggestions. Auto-detects nmap vs. gobuster/feroxbuster/dirb output; you
  can force it with `--tool`. Appends a timestamped section to the target's
  notebook unless `--no-notebook` is passed.
- `ctfc notes <target>` — print the accumulated Markdown recon log for a
  target (or just its path with `--path`).
- `ctfc suggest` — query the rule engine directly for a service/version
  without needing a scan file, e.g. while triaging a finding mid-session.

## Offline guarantee

By default, ctf-copilot makes **zero network calls**. The rule engine is
pure, local pattern matching against a bundled YAML file. The only way to
introduce network activity is to explicitly pass `--llm` on `ctfc feed`, which
then talks to either:

- a local **Ollama** server (`http://localhost:11434` by default — still
  100% local, nothing leaves your machine), or
- an **OpenAI-compatible API**, if you set `CTFC_LLM_BACKEND=openai` and
  `OPENAI_API_KEY` (requires `pip install "ctf-copilot[llm]"`).

If neither is configured/reachable, `--llm` prints a clear warning and falls
back to rule-based suggestions only — it never crashes your recon session.

## Notebook format

Findings and suggestions are appended to
`.ctf-copilot/<target>/notes.md` (relative to your current working
directory), one timestamped section per `ctfc feed` call. It's a normal
Markdown file — open it in your editor, commit it to your CTF writeup repo,
paste it into your report, whatever.

## Architecture

```
                    ┌────────────────┐
   raw tool output  │                │
  ───────────────▶  │   parsers/     │  nmap.py, dirscan.py, detect.py
   (file / stdin)   │                │  → ParseResult (ports, paths)
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐      rules/data/rules.yaml
                    │  rules/engine  │◀────  (contributor-editable,
                    │                │        no Python required)
                    └───────┬────────┘
                            │ Suggestion[]
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌───────────┐ ┌───────────┐ ┌────────────┐
        │  cli.py   │ │notebook.py│ │  llm.py    │
        │ (rich UI) │ │ (.md log) │ │ (optional, │
        │           │ │           │ │  opt-in)   │
        └───────────┘ └───────────┘ └────────────┘
```

## Rule coverage (built-in)

- **Ports/services:** FTP, SSH, Telnet, SMTP, DNS, HTTP/HTTPS, SMB, RPC/NFS,
  MSSQL, MySQL, PostgreSQL, RDP, WinRM, SNMP, LDAP, Redis, IMAP/POP3.
- **Known vulnerable versions:** vsftpd 2.3.4 backdoor, ProFTPd 1.3.3c
  backdoor, old Samba (CVE-2017-7494 / usermap_script), outdated Apache
  (path-traversal RCE range), outdated PHP, IIS/WebDAV.
- **Directory-discovery follow-ups:** exposed `.git`, `.env`, backup/archive
  files, WordPress, phpMyAdmin, admin panels, upload endpoints, API roots,
  config files.

Adding a rule is a YAML edit, not a code change — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Testing

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The test suite covers the nmap and dirbuster/gobuster/feroxbuster/dirb
parsers against realistic sample output, the rule engine's matching and
priority-ordering logic, and the notebook writer.

## Project keywords

`ctf` · `pentesting` · `recon` · `enumeration` · `security-tools` ·
`cli` · `nmap` · `gobuster` · `infosec`

*(If you're the repo owner: add these as GitHub topics under Settings →
General → Topics for discoverability — Claude cannot set them via the API.)*

## License

MIT — see [LICENSE](LICENSE).
