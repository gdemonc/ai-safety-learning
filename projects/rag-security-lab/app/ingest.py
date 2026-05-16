from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

from config import CHROMA_DIR, CHUNK_OVERLAP, CHUNK_SIZE, COLLECTION_NAME, DATA_DIR, EMBEDDING_MODEL, ensure_directories


def read_documents(root: Path) -> list[tuple[Path, str]]:
    docs: list[tuple[Path, str]] = []
    for path in sorted(root.rglob("*.md")):
        docs.append((path, path.read_text(encoding="utf-8")))
    return docs


def chunk_text(text: str, chunk_size: int, chunk_overlap: int) -> list[str]:
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - chunk_overlap, start + 1)
    return chunks


def build_records(data_root: Path) -> list[dict]:
    records: list[dict] = []
    for path, text in read_documents(data_root):
        for chunk_index, chunk in enumerate(
            chunk_text(text, CHUNK_SIZE, CHUNK_OVERLAP)
        ):
            rel_path = path.relative_to(DATA_DIR).as_posix()
            chunk_id = hashlib.sha256(f"{rel_path}:{chunk_index}:{chunk}".encode("utf-8")).hexdigest()
            records.append(
                {
                    "id": chunk_id,
                    "document": chunk,
                    "metadata": {
                        "source": rel_path,
                        "chunk_index": chunk_index,
                    },
                }
            )
    return records


def ingest(data_root: Path, reset: bool) -> None:
    ensure_directories()
    if reset and CHROMA_DIR.exists():
        shutil.rmtree(CHROMA_DIR)
        ensure_directories()

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    embedding_model = SentenceTransformer(EMBEDDING_MODEL)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    records = build_records(data_root)
    if not records:
        print("No markdown documents found.")
        return

    documents = [r["document"] for r in records]
    embeddings = embedding_model.encode(documents).tolist()
    ids = [r["id"] for r in records]
    metadatas = [r["metadata"] for r in records]

    existing = set(collection.get(include=[])["ids"])
    new_records = [
        (record_id, doc, meta, emb)
        for record_id, doc, meta, emb in zip(ids, documents, metadatas, embeddings)
        if record_id not in existing
    ]

    if not new_records:
        print("No new chunks to ingest.")
        return

    collection.add(
        ids=[r[0] for r in new_records],
        documents=[r[1] for r in new_records],
        metadatas=[r[2] for r in new_records],
        embeddings=[r[3] for r in new_records],
    )
    print(f"Ingested {len(new_records)} chunks into collection '{COLLECTION_NAME}'.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        choices=["clean", "poisoned", "all"],
        default="clean",
        help="Which dataset folder to ingest.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset the local Chroma database before ingesting.",
    )
    args = parser.parse_args()

    if args.dataset == "clean":
        data_root = DATA_DIR / "clean"
    elif args.dataset == "poisoned":
        data_root = DATA_DIR / "poisoned"
    else:
        data_root = DATA_DIR

    ingest(data_root, reset=args.reset)


if __name__ == "__main__":
    main()
