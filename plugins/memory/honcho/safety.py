"""Fail-closed content checks for every Honcho write path."""

from __future__ import annotations

import re


_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", re.IGNORECASE),
    re.compile(
        r"[\"']?(?:api[_-]?key|authorization|cookie|password|passwd|secret|token|credential|auth|"
        r"aws_secret_access_key|aws_session_token|private_key)[\"']?"
        r"\s*[:=]\s*[\"']?[^\s\"',;}{]{8,}",
        re.IGNORECASE,
    ),
    re.compile(
        r"[\"']?authorization[\"']?\s*:\s*[\"']?(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk(?:-proj)?-[A-Za-z0-9_-]{16,}\b"),
)


_QA_MARKER = re.compile(
    r"\b(?:HONCHO|HERMES|PI|PASEO|CLAUDE_MEM)(?:_[A-Z0-9]+)*"
    r"(?:_TEST|_SMOKE|_E2E|_PROBE|_CANARY|_MARKER)(?:_[A-Z0-9]+)*\b",
    re.IGNORECASE,
)
_EXACT_REPLY = re.compile(r"\breply\s+(?:with\s+)?(?:exactly|only)\b", re.IGNORECASE)
_HONCHO_SELF_TEST = re.compile(
    r"\bhoncho_(?:search|chat|remember)\b.{0,160}\b(?:find|quote|reply|marker|test)\b",
    re.IGNORECASE,
)
_CONNECTIVITY_TEST = re.compile(r"\b(?:connected|connection|wired up|available)\b", re.IGNORECASE)
_TOOL_NAME = re.compile(
    r"\b(?:composio|mcp|mcps|agent-browser|honcho|claude[- ]?mem)\b", re.IGNORECASE
)


def contains_secret(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in _SECRET_PATTERNS)


def is_low_value_qa_prompt(text: str) -> bool:
    prompt = (text or "").strip()
    if not prompt or len(prompt) > 600:
        return False
    return bool(
        _QA_MARKER.search(prompt)
        or _EXACT_REPLY.search(prompt)
        or _HONCHO_SELF_TEST.search(prompt)
        or (_CONNECTIVITY_TEST.search(prompt) and _TOOL_NAME.search(prompt))
    )


def safe_exchange(user_text: str, assistant_text: str) -> bool:
    if not user_text or not assistant_text or is_low_value_qa_prompt(user_text):
        return False
    return not contains_secret(user_text) and not contains_secret(assistant_text)
