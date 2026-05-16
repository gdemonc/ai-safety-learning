from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
CHROMA_DIR = BASE_DIR / ".chroma"
COLLECTION_NAME = os.getenv("RAG_COLLECTION_NAME", "rag_security_lab")

EMBEDDING_MODEL = os.getenv(
    "RAG_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
)
CHUNK_SIZE = int(os.getenv("RAG_CHUNK_SIZE", "500"))
CHUNK_OVERLAP = int(os.getenv("RAG_CHUNK_OVERLAP", "100"))
TOP_K = int(os.getenv("RAG_TOP_K", "3"))

LLM_PROVIDER = os.getenv("RAG_LLM_PROVIDER", "ollama").strip().lower()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


def ensure_directories() -> None:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
