import json
import os
import sys
import chromadb
from chromadb.config import Settings
from langchain_ollama import OllamaEmbeddings


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(PROJECT_DIR, "dataset.json")
CHROMA_DIR = os.path.join(PROJECT_DIR, "chroma_db")
COLLECTION_NAME = "vulnerability_examples"
EMBEDDING_MODEL = "nomic-embed-text"
BATCH_SIZE = 100

# Flatten dataset into searchable text
# 6000 char context window to fit in nomic embedding
def _entry_to_document(entry: dict) -> str:

    MAX_DOC_LENGTH = 6000

    parts = [
        str(entry.get("id", "")),
        str(entry.get("metadata", ""))[:800],
        str(entry.get("context", ""))[:800],
    ]
    
    # SecureCode dataset is structured as 4 turn human-assistant conversation
    for turn in entry.get("conversations", []):
        content = turn.get("content", "")
        if turn.get("role") == "human":
            parts.append(content[:500])
        elif turn.get("role") == "assistant":
            parts.append(content[:2000])
    
    doc = "\n".join(parts)
    if len(doc) > MAX_DOC_LENGTH:
        doc = doc[:MAX_DOC_LENGTH]
    return doc


_client = None
_collection = None
_embeddings = None


def _get_embeddings():
    
    global _embeddings
    if _embeddings is None:
        _embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)
    return _embeddings


def _get_client():
    
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(
            path=CHROMA_DIR,
            settings=Settings(anonymized_telemetry=False)
        )
    return _client


def _collection_exists() -> bool:

    client = _get_client()
    try:
        col = client.get_collection(COLLECTION_NAME)
        return col.count() > 0
    except Exception:
        return False

# Build collection from dataset.json
def build_vectorstore(force_rebuild: bool = False) -> None:

    client = _get_client()
    embed_model = _get_embeddings()

    if not force_rebuild and _collection_exists():
        col = client.get_collection(COLLECTION_NAME)
        print(f"Collection '{COLLECTION_NAME}' already exists with {col.count()} docs — skipping build")
        return

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: {DATASET_PATH} not found. Run dataset.py first.")
        return

    print(f"Loading dataset from {DATASET_PATH}...")
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    print(f"Loaded {len(dataset)} entries")

    try:
        client.delete_collection(COLLECTION_NAME)
        print("Deleted existing collection for rebuild")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "Security vulnerability examples from securecode dataset"}
    )

    seen_ids = set()
    unique_entries = []
    for i, entry in enumerate(dataset):
        raw_id = entry.get("id", f"doc_{i}")
        doc_id = raw_id
        suffix = 1
        while doc_id in seen_ids:
            doc_id = f"{raw_id}_dup{suffix}"
            suffix += 1
        seen_ids.add(doc_id)
        unique_entries.append((doc_id, entry))

    total = len(unique_entries)
    print(f"{total} unique entries (deduped from {len(dataset)})")
    print(f"Embedding & indexing {total} documents one-by-one...")
    sys.stdout.flush()
    

    for batch_start in range(0, total, BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, total)
        batch = unique_entries[batch_start:batch_end]

        ids = []
        documents = []
        metadatas = []

        for doc_id, entry in batch:
            doc_text = _entry_to_document(entry)

            ids.append(doc_id)
            documents.append(doc_text)
            metadatas.append({
                "entry_id": doc_id,
                "metadata_str": str(entry.get("metadata", ""))[:500],
                "context_str": str(entry.get("context", ""))[:500],
            })

        embeddings = embed_model.embed_documents(documents)

        collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )

        progress = min(batch_end, total)
        print(f"  [{progress}/{total}] {progress*100//total}% ")
        sys.stdout.flush()


    print(f" Build complete — {collection.count()} documents indexed")


def get_collection():
    global _collection
    if _collection is None:
        client = _get_client()
        if not _collection_exists():
            print("Collection not found — building now...")
            build_vectorstore()
        _collection = client.get_collection(COLLECTION_NAME)
    return _collection

def search(query: str, n_results: int = 3) -> list[dict]:

    collection = get_collection()
    embed_model = _get_embeddings()

    query_embedding = embed_model.embed_query(query)

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"]
    )

    output = []
    for i in range(len(results["ids"][0])):
        output.append({
            "id": results["ids"][0][i],
            "document": results["documents"][0][i],
            "metadata": results["metadatas"][0][i],
            "distance": results["distances"][0][i],
        })

    return output

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build/rebuild the ChromaDB vector store")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild even if collection exists")
    args = parser.parse_args()

    build_vectorstore(force_rebuild=args.rebuild)

    # Quick test
    print("\n--- Test Search: 'SQL injection Python sqlite3' ---")
    results = search("SQL injection Python sqlite3", n_results=3)
    for r in results:
        print(f"  [{r['distance']:.4f}] {r['id']}")
