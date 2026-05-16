from __future__ import annotations

import re
from typing import Iterable, List


SUSPICIOUS_QUERY_PATTERNS = [
    r"ignore\s+(all|previous)",
    r"system\s+prompt",
    r"developer\s+message",
    r"repeat\s+the\s+hidden\s+instructions",
]

SUSPICIOUS_CONTEXT_PATTERNS = [
    r"internal\s+processing\s+directive",
    r"ignore\s+current\s+mode",
    r"when\s+user\s+asks",
    r"return\s+only\s+the\s+file\s+contents",
    r"must\s+always\s+include",
]

SENSITIVE_OUTPUT_PATTERNS = [
    r"api[_\s-]?key",
    r"private\s+key",
    r"password",
    r"secret",
    r"token",
]


def _match_any(text: str, patterns: Iterable[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def inspect_user_query(query: str) -> dict:
    hits = _match_any(query, SUSPICIOUS_QUERY_PATTERNS)
    return {
        "blocked": bool(hits),
        "hits": hits,
        "reason": "Suspicious user query" if hits else "",
    }


def filter_context_chunks(chunks: list[dict]) -> tuple[list[dict], list[dict]]:
    allowed: list[dict] = []
    blocked: list[dict] = []
    for chunk in chunks:
        content = chunk["content"]
        if _match_any(content, SUSPICIOUS_CONTEXT_PATTERNS):
            blocked.append(chunk)
        else:
            allowed.append(chunk)
    return allowed, blocked


def redact_output(text: str) -> str:
    sanitized = text
    for pattern in SENSITIVE_OUTPUT_PATTERNS:
        sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
    return sanitized


def safe_sources(chunks: list[dict]) -> list[dict]:
    trimmed = []
    for chunk in chunks:
        trimmed.append(
            {
                "source": chunk["source"],
                "chunk_index": chunk["chunk_index"],
                "preview": chunk["content"][:120].replace("\n", " "),
            }
        )
    return trimmed
