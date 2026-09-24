
import pytest

from ctf_copilot import llm
from ctf_copilot.models import ParseResult, PortFinding


def test_resolve_config_defaults_to_ollama(monkeypatch):
    monkeypatch.delenv("CTFC_LLM_BACKEND", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = llm.resolve_config()
    assert config.backend == "ollama"
    assert config.host == llm.DEFAULT_OLLAMA_HOST


def test_resolve_config_uses_openai_when_api_key_present(monkeypatch):
    monkeypatch.delenv("CTFC_LLM_BACKEND", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    config = llm.resolve_config()
    assert config.backend == "openai"
    assert config.api_key == "sk-test"


def test_parse_llm_response_extracts_text_and_command():
    text = "1. Check for X || nmap -sV target\n2. Try Y || echo hi\n"
    suggestions = llm._parse_llm_response(text)
    assert len(suggestions) == 2
    assert suggestions[0].text == "Check for X"
    assert suggestions[0].command == "nmap -sV target"
    assert suggestions[0].source == "llm"


def test_parse_llm_response_handles_missing_command():
    suggestions = llm._parse_llm_response("- Just a plain suggestion\n")
    assert len(suggestions) == 1
    assert suggestions[0].command == ""


def test_ollama_unreachable_raises_llm_error(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    config = llm.LLMConfig(backend="ollama", host="http://localhost:11434", model="llama3")

    with pytest.raises(llm.LLMError, match="Could not reach Ollama"):
        llm._query_ollama(config, "prompt text")


def test_openai_backend_without_api_key_raises(monkeypatch):
    monkeypatch.setenv("CTFC_LLM_BACKEND", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = ParseResult(tool="nmap")
    result.ports.append(PortFinding(port=21, service="ftp"))

    with pytest.raises(llm.LLMError, match="OPENAI_API_KEY"):
        llm.get_llm_suggestions(result, target="10.10.10.5")
