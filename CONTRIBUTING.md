# Contributing to ctf-copilot

Thanks for considering a contribution. The project is intentionally small and
readable — most contributions fall into one of three buckets below.

## Dev setup

```bash
git clone https://github.com/HMJ07/ctf-copilot.git
cd ctf-copilot
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
ruff check .
```

## Adding a new rule (the easy, high-value contribution)

Rules live in `src/ctf_copilot/rules/data/rules.yaml` — plain data, no Python
required. There are two kinds:

### Port rule

Fires when a scanned port matches a service name (and, optionally, a port
number and/or a regex against the banner string nmap reports).

```yaml
port_rules:
  - id: my-new-rule          # unique, kebab-case
    services: [ftp]          # lowercase service names to match
    ports: [21]              # optional: also require one of these ports
    banner_regex: "foo\\d+"  # optional: regex against the banner (case-insensitive)
    suggestions:
      - text: "Human-readable explanation of what to try and why."
        command: "some-tool --target {target} --port {port}"
        priority: 3           # 1 (nice-to-have) .. 5 (drop everything)
```

`{target}` and `{port}` are substituted automatically. A rule must specify at
least `services` or `ports` — wildcard "matches everything" rules aren't
allowed, to keep suggestions relevant.

### Path rule

Fires when a discovered URL path matches a regex (e.g. from gobuster).

```yaml
path_rules:
  - id: my-path-rule
    path_regex: "\\.git(/|$)"
    suggestions:
      - text: "Explain the finding."
        command: "some-tool http://{target}{path}"
        priority: 4
```

`{target}` and `{path}` are available as placeholders here.

### Guidelines for good rules

- Keep `text` factual and specific — name the CVE or technique, not just "this
  might be interesting".
- Set `priority` honestly: 5 is reserved for near-certain, high-impact wins
  (known backdoors, unauthenticated RCE). Most rules should be 1-3.
- Prefer a narrow `banner_regex` over a broad one — false positives erode
  trust in the tool.
- Add or extend a test in `tests/test_rules_engine.py` for any new rule that
  has non-obvious matching logic.

Once you've edited the YAML, run `pytest` — the existing suite loads the real
bundled rule file and will fail loudly on a YAML/schema mistake.

## Adding/improving a parser

Parsers live in `src/ctf_copilot/parsers/`. Each one takes raw text and
returns a `ctf_copilot.models.ParseResult`. When adding support for a new
tool's output format:

1. Add a `parse_<tool>()` function following the pattern in `nmap.py` or
   `dirscan.py`.
2. Register a detection heuristic in `parsers/detect.py` so `ctfc feed` can
   auto-detect it.
3. Add realistic sample output (copy-pasted or faithfully reconstructed from
   the real tool) to a test file under `tests/`, covering the happy path and
   at least one edge case (empty input, unusual formatting).

## Code style

- Formatted/linted with `ruff` (`ruff check .`); CI enforces this.
- Type hints are encouraged but not mandatory everywhere — favor clarity.
- Keep the core rule-engine + parsers dependency-free (stdlib + `PyYAML` +
  `rich` only). Anything needing extra dependencies belongs behind the
  optional `llm` extra.

## Reporting bugs / requesting rules

Open a GitHub issue. For "please add a rule for X", a link to the relevant
CVE/technique writeup is very welcome.
