
import json
import re
import os
from string import whitespace
import time
import numpy as np
from pathlib import Path


# Configuration 

INPUT_FILES = [
    "data/v18.1/enterprise-attack.json",
    "data/v18.1/ics-attack.json",
    "data/v18.1/mobile-attack.json",
]

OUTPUT_DIR = "./vector_embeddings"


EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

# Batch size for encoding — reduce if you hit memory errors
BATCH_SIZE = 64

# Max characters per chunk before truncation warning (model limit is ~512 tokens)
MAX_CHARS = 1800



# Text cleaning 

def clean(text: str) -> str:
    
    if not text:
        return ""
    # [Label](url) → Label
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # (Citation: Foo 2020) → ""
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    # <code>content</code> → content
    text = re.sub(r'<code>(.*?)</code>', r'\1', text, flags=re.DOTALL)
    # collapse whitespace
    text = ' '.join(text.split())
    return text.strip()


# Chunk builders 

def build_technique_chunks(objects: list) -> list:
    
    # One chunk per technique — combines description + tactic + platform context
    # into a single rich text so the embedding captures full semantic meaning.
    
    chunks = []
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked"):
            continue

        attack_id  = _attack_id(o)
        name       = o.get("name", "")
        desc       = clean(o.get("description", ""))
        tactics    = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                      if "mitre" in p.get("kill_chain_name", "")]
        platforms  = o.get("x_mitre_platforms", [])
        domains    = o.get("x_mitre_domains", [])
        is_sub     = o.get("x_mitre_is_subtechnique", False)

        if not desc:
            continue

        # Prefix context so the embedding encodes tactic/platform semantics
        prefix = f"Technique {attack_id}: {name}."
        if tactics:
            prefix += f" Tactic: {', '.join(tactics)}."
        if platforms:
            prefix += f" Platforms: {', '.join(platforms)}."

        text = f"{prefix} {desc}"

        chunks.append({
            "chunk_id":   f"technique::{attack_id}",
            "text":       text[:MAX_CHARS],
            "metadata": {
                "type":          "technique",
                "attack_id":     attack_id,
                "name":          name,
                "tactics":       tactics,
                "platforms":     platforms,
                "domains":       domains,
                "is_subtechnique": is_sub,
                "stix_id":       o.get("id", ""),
                "url":           _attack_url(o),
            }
        })
    return chunks


def build_relationship_chunks(objects: list) -> list:
    
    # One chunk per relationship that has a description.
    
    lookup = {o["id"]: o for o in objects if "id" in o}
    chunks = []

    for o in objects:
        if o.get("type") != "relationship":
            continue
        desc = clean(o.get("description", ""))
        if not desc:
            continue

        rel_type = o.get("relationship_type", "")
        src      = lookup.get(o.get("source_ref", ""), {})
        tgt      = lookup.get(o.get("target_ref", ""), {})
        src_name = src.get("name", "")
        tgt_name = tgt.get("name", "")
        src_type = src.get("type", "")
        tgt_type = tgt.get("type", "")
        src_id   = _attack_id(src)
        tgt_id   = _attack_id(tgt)

        # Contextual prefix
        prefix = f"{src_name} ({src_id}) {rel_type} {tgt_name} ({tgt_id}):"
        text   = f"{prefix} {desc}"

        chunks.append({
            "chunk_id": f"relationship::{o.get('id','')}",
            "text":     text[:MAX_CHARS],
            "metadata": {
                "type":          "relationship",
                "relationship_type": rel_type,
                "source_name":   src_name,
                "source_type":   src_type,
                "source_id":     src_id,
                "target_name":   tgt_name,
                "target_type":   tgt_type,
                "target_id":     tgt_id,
                "stix_id":       o.get("id", ""),
            }
        })
    return chunks


def build_entity_chunks(objects: list, obj_type: str, label: str) -> list:
    
    # Generic chunk builder for groups, malware, tools, mitigations.
    # Prefixes the entity name and ID so context is embedded alongside content.

    chunks = []
    for o in objects:
        if o.get("type") != obj_type or o.get("revoked"):
            continue

        attack_id = _attack_id(o)
        name      = o.get("name", "")
        desc      = clean(o.get("description", ""))
        if not desc:
            continue

        aliases   = o.get("aliases") or o.get("x_mitre_aliases") or []
        platforms = o.get("x_mitre_platforms", [])

        prefix = f"{label} {attack_id}: {name}."
        if aliases:
            others = [a for a in aliases if a != name]
            if others:
                prefix += f" Also known as: {', '.join(others[:4])}."
        if platforms:
            prefix += f" Platforms: {', '.join(platforms)}."

        text = f"{prefix} {desc}"

        chunks.append({
            "chunk_id": f"{label.lower()}::{attack_id or o.get('id','')}",
            "text":     text[:MAX_CHARS],
            "metadata": {
                "type":      label.lower(),
                "attack_id": attack_id,
                "name":      name,
                "aliases":   aliases,
                "platforms": platforms,
                "domains":   o.get("x_mitre_domains", []),
                "stix_id":   o.get("id", ""),
                "url":       _attack_url(o),
            }
        })
    return chunks


# Utils

def _attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if "mitre-attack" in ref.get("source_name", ""):
            return ref.get("external_id", "")
    return ""


def _attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if "mitre-attack" in ref.get("source_name", ""):
            return ref.get("url", "")
    return ""


def load_and_merge(files: list) -> list:
    all_objs = []
    for path in files:
        print(f"  Loading {path} ...")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        objs = data.get("objects", data) if isinstance(data, dict) else data
        all_objs.extend(objs)
        print(f"           {len(objs):,} objects")

    seen, unique = set(), []
    for o in all_objs:
        oid = o.get("id")
        if oid and oid not in seen:
            seen.add(oid)
            unique.append(o)

    print(f"\n  Unique objects after dedup: {len(unique):,}")
    return unique


# Main pipeline 

def extract_chunks(objects: list) -> list:
    # Build all text chunks from STIX objects.
    chunks = []

    t = build_technique_chunks(objects)
    r = build_relationship_chunks(objects)
    g = build_entity_chunks(objects, "intrusion-set",  "Group")
    m = build_entity_chunks(objects, "malware",        "Malware")
    s = build_entity_chunks(objects, "tool",           "Tool")
    c = build_entity_chunks(objects, "course-of-action", "Mitigation")

    chunks = t + r + g + m + s + c

    print(f"\n  Chunk summary:")
    print(f"    Techniques     {len(t):>6,}")
    print(f"    Relationships  {len(r):>6,}")
    print(f"    Groups         {len(g):>6,}")
    print(f"    Malware        {len(m):>6,}")
    print(f"    Tools          {len(s):>6,}")
    print(f"    Mitigations    {len(c):>6,}")
    print(f"    ─────────────────────")
    print(f"    Total          {len(chunks):>6,}")

    return chunks


def generate_embeddings(chunks: list, model_name: str, batch_size: int) -> np.ndarray:
    # Encode all chunks using sentence-transformers.
    from sentence_transformers import SentenceTransformer
    from tqdm import tqdm

    print(f"\n  Loading model: {model_name} ...")
    model = SentenceTransformer(model_name)
    dim = model.get_sentence_embedding_dimension()
    print(f"  Embedding dimension: {dim}")

    texts = [c["text"] for c in chunks]
    total = len(texts)
    embeddings = []

    print(f"  Encoding {total:,} chunks (batch size {batch_size}) ...")
    t0 = time.time()

    for i in tqdm(range(0, total, batch_size), unit="batch"):
        batch = texts[i : i + batch_size]
        vecs  = model.encode(batch, show_progress_bar=False, normalize_embeddings=True)
        embeddings.append(vecs)

    vectors = np.vstack(embeddings)
    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s  ({total/elapsed:.0f} chunks/sec)")
    print(f"  Embedding matrix shape: {vectors.shape}")
    return vectors


def save_outputs(chunks: list, vectors: np.ndarray, output_dir: str):
    # Save embeddings as .npz and chunk manifest as .json.
    os.makedirs(output_dir, exist_ok=True)

    # Save embeddings
    npz_path = os.path.join(output_dir, "embeddings.npz")
    ids      = np.array([c["chunk_id"] for c in chunks])
    texts    = np.array([c["text"]     for c in chunks])
    np.savez_compressed(
        npz_path,
        vectors=vectors,
        ids=ids,
        texts=texts,
    )
    print(f"\n  Saved: {npz_path}  ({os.path.getsize(npz_path) / 1e6:.1f} MB)")

    # Save chunk manifest (metadata for KG-hybrid filtering)
    json_path = os.path.join(output_dir, "chunks.json")
    manifest  = [
        {"chunk_id": c["chunk_id"], "text": c["text"], "metadata": c["metadata"]}
        for c in chunks
    ]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"  Saved: {json_path}  ({os.path.getsize(json_path) / 1e6:.1f} MB)")


def load_embeddings(output_dir: str):

    # Helper to reload saved embeddings for downstream use.

    npz = np.load(os.path.join(output_dir, "embeddings.npz"), allow_pickle=True)
    vectors = npz["vectors"]
    ids     = npz["ids"].tolist()
    texts   = npz["texts"].tolist()

    with open(os.path.join(output_dir, "chunks.json"), encoding="utf-8") as f:
        chunks = json.load(f)

    return vectors, ids, texts, chunks




def main():
    print("=" * 55)
    print("  MITRE ATT&CK Vector Embedding Generator")
    print("=" * 55)

    # 1. Validate input files
    missing = [f for f in INPUT_FILES if not os.path.exists(f)]
    if missing:
        raise FileNotFoundError(f"Missing files: {', '.join(missing)}")

    # 2. Load STIX data
    print("\n[1/4] Loading STIX data")
    objects = load_and_merge(INPUT_FILES)

    # 3. Extract text chunks
    print("\n[2/4] Extracting text chunks")
    chunks = extract_chunks(objects)

    # 4. Generate embeddings
    print("\n[3/4] Generating embeddings")
    vectors = generate_embeddings(chunks, EMBEDDING_MODEL, BATCH_SIZE)

    # 5. Save outputs
    print("\n[4/4] Saving outputs")
    save_outputs(chunks, vectors, OUTPUT_DIR)

    # print("\nDone.")
    # print(f"\nTo reload embeddings in another script:")
    # print(f"  from mitre_embeddings import load_embeddings")
    # print(f"  vectors, ids, texts, chunks = load_embeddings('{OUTPUT_DIR}')")


if __name__ == "__main__":
    main()