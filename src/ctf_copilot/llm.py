"""Optional LLM backend for open-ended suggestions.

This module is never imported unless the user explicitly passes ``--llm`` on
the CLI, and it never makes a network call unless that flag is set. Two
backends are supported:

* **Ollama** (default): a local server at ``$OLLAMA_HOST`` (default
  ``http://localhost:11434``). Nothing leaves the machine.
* **OpenAI-compatible API**: used when ``CTFC_LLM_BACKEND=openai`` (or when
  ``OPENAI_API_KEY`` is set and Ollama is unreachable). Requires the
  ``ctf-copilot[llm]`` extra (``requests``).

If neither backend is reachable/configured, callers get a clear, actionable
error instead of a stack trace.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from ctf_copilot.models import ParseResult, Suggestion

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"

REQUEST_TIMEOUT_SECONDS = 20


class LLMError(RuntimeError):
    """Raised when the LLM backend can't be reached or isn't configured."""


@dataclass
class LLMConfig:
    backend: str  # "ollama" or "openai"
    host: str
    model: str
    api_key: str | None = None


def resolve_config() -> LLMConfig:
    backend = os.environ.get("CTFC_LLM_BACKEND", "").lower()
    api_key = os.environ.get("OPENAI_API_KEY")

    if not backend:
        backend = "openai" if api_key else "ollama"

    if backend == "openai":
        return LLMConfig(
            backend="openai",
            host=os.environ.get("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL),
            model=os.environ.get("CTFC_LLM_MODEL", DEFAULT_OPENAI_MODEL),
            api_key=api_key,
        )

    return LLMConfig(
        backend="ollama",
        host=os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST),
        model=os.environ.get("CTFC_LLM_MODEL", DEFAULT_OLLAMA_MODEL),
    )


def _build_prompt(result: ParseResult, target: str, existing: list[Suggestion]) -> str:
    lines = [
        "You are a CTF/pentest recon assistant. Given the following scan findings, "
        "suggest 2-4 additional, concrete, non-obvious next enumeration or exploitation "
        "steps that are not already covered. Be specific and include exact commands. "
        "Keep each suggestion to one or two sentences plus a command.",
        "",
        f"Target: {target or 'unknown'}",
        "",
        "Findings:",
    ]
    for port_finding in result.ports:
        lines.append(
            f"- port {port_finding.port}/{port_finding.protocol} "
            f"({port_finding.service}): {port_finding.banner}"
        )
    for path_finding in result.paths:
        lines.append(f"- path {path_finding.path} (status {path_finding.status})")

    if existing:
        lines.append("")
        lines.append("Already-suggested steps (do not repeat these):")
        for suggestion in existing:
            lines.append(f"- {suggestion.text}")

    lines.append("")
    lines.append(
        "Respond as a plain numbered list, one suggestion per line, "
        "formatted as: <suggestion text> || <command>"
    )
    return "\n".join(lines)


def _parse_llm_response(text: str) -> list[Suggestion]:
    suggestions = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("-*").strip()
        # Strip leading numbering like "1." or "1)"
        line = _strip_numbering(line)
        if not line:
            continue
        if "||" in line:
            body, command = line.split("||", 1)
        else:
            body, command = line, ""
        body = body.strip()
        command = command.strip()
        if body:
            suggestions.append(
                Suggestion(text=body, command=command, priority=2, source="llm")
            )
    return suggestions


def _strip_numbering(line: str) -> str:
    import re

    return re.sub(r"^\d+[.)]\s*", "", line)


def get_llm_suggestions(
    result: ParseResult, target: str = "", existing: list[Suggestion] | None = None
) -> list[Suggestion]:
    """Query the configured LLM backend for extra suggestions.

    Raises LLMError with a human-readable message if the backend is not
    reachable/configured. Never called unless the caller opts in.
    """
    config = resolve_config()
    prompt = _build_prompt(result, target, existing or [])

    if config.backend == "openai":
        return _query_openai(config, prompt)
    return _query_ollama(config, prompt)


def _query_ollama(config: LLMConfig, prompt: str) -> list[Suggestion]:
    url = config.host.rstrip("/") + "/api/generate"
    payload = json.dumps(
        {"model": config.model, "prompt": prompt, "stream": False}
    ).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError) as exc:
        raise LLMError(
            f"Could not reach Ollama at {config.host}. Is `ollama serve` running? "
            f"(underlying error: {exc})"
        ) from exc

    text = body.get("response", "")
    return _parse_llm_response(text)


def _query_openai(config: LLMConfig, prompt: str) -> list[Suggestion]:
    if not config.api_key:
        raise LLMError(
            "CTFC_LLM_BACKEND=openai but OPENAI_API_KEY is not set. "
            "Export OPENAI_API_KEY, or unset CTFC_LLM_BACKEND to use local Ollama instead."
        )

    try:
        import requests
    except ImportError as exc:
        raise LLMError(
            "The OpenAI-compatible backend requires the optional 'llm' extra. "
            "Install it with: pip install 'ctf-copilot[llm]'"
        ) from exc

    url = config.host.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }
    try:
        response = requests.post(
            url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:  # noqa: BLE001 - surface any failure as LLMError
        raise LLMError(f"OpenAI-compatible API request failed: {exc}") from exc

    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise LLMError(f"Unexpected response shape from LLM backend: {data}") from exc

    return _parse_llm_response(text)
