"""Parsers turn raw tool output (text) into structured findings (models.ParseResult)."""

from ctf_copilot.parsers.detect import detect_and_parse, parse_with
from ctf_copilot.parsers.dirscan import parse_dirscan
from ctf_copilot.parsers.nmap import parse_nmap

__all__ = ["detect_and_parse", "parse_with", "parse_nmap", "parse_dirscan"]
