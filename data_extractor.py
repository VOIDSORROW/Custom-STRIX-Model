# Script for extracting STRIX data.


import mitreattack
# Using (download_attack_stix --all) command, the complete STIX data can be downloaded.
# (download_attack_stix --stix 2.1) for strix 2.1.

# imports during STRIX to CSV conversion.
import json
import csv
import os
import sys
from pathlib import Path

    
    
INPUT_FILES = [
    "D:/M.Tech/Projects/Custom-STRIX-Model/data/v18.1/enterprise-attack.json",
    "D:/M.Tech/Projects/Custom-STRIX-Model/data/v18.1/ics-attack.json",
    "D:/M.Tech/Projects/Custom-STRIX-Model/data/v18.1/mobile-attack.json",
]
 
OUTPUT_DIR = "D:/M.Tech/Projects/Custom-STRIX-Model/data/strix-csv"
     
     
     
def load_bundle(path: str) -> list:
    # Load a STIX 2.x bundle and return its objects list.
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("objects", [])
    if isinstance(data, list):
        return data
    raise ValueError(f"Unrecognised STIX structure in: {path}")
 
 
def attack_id(obj: dict) -> str:
    # Return the ATT&CK external ID (T1059, G0016, S0002 ...).
    for ref in obj.get("external_references", []):
        if "mitre-attack" in ref.get("source_name", ""):
            return ref.get("external_id", "")
    return ""
 
 
def attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if "mitre-attack" in ref.get("source_name", ""):
            return ref.get("url", "")
    return ""
 
 
def pipe(items: list) -> str:
    # Flatten a list to a pipe-separated string.
    return " | ".join(str(i) for i in items if i)
 
 
def flat(text: str) -> str:
    # Collapse newlines / extra whitespace in description fields.
    return " ".join(text.replace("\n", " ").split()) if text else ""
 
 
# Per-type extractors
 
def techniques(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked"):
            continue
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if "mitre" in p.get("kill_chain_name", "")]
        rows.append({
            "attack_id":            attack_id(o),
            "name":                 o.get("name", ""),
            "is_subtechnique":      o.get("x_mitre_is_subtechnique", False),
            "tactics":              pipe(tactics),
            "platforms":            pipe(o.get("x_mitre_platforms", [])),
            "data_sources":         pipe(o.get("x_mitre_data_sources", [])),
            "permissions_required": pipe(o.get("x_mitre_permissions_required", [])),
            "defense_bypassed":     pipe(o.get("x_mitre_defense_bypassed", [])),
            "description":          flat(o.get("description", "")),
            "detection":            flat(o.get("x_mitre_detection", "")),
            "contributors":         pipe(o.get("x_mitre_contributors", [])),
            "version":              o.get("x_mitre_version", ""),
            "created":              o.get("created", ""),
            "modified":             o.get("modified", ""),
            "stix_id":              o.get("id", ""),
            "url":                  attack_url(o),
        })
    return rows
 
 
def tactics(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "x-mitre-tactic":
            continue
        rows.append({
            "attack_id":   attack_id(o),
            "name":        o.get("name", ""),
            "shortname":   o.get("x_mitre_shortname", ""),
            "description": flat(o.get("description", "")),
            "created":     o.get("created", ""),
            "modified":    o.get("modified", ""),
            "stix_id":     o.get("id", ""),
            "url":         attack_url(o),
        })
    return rows
 
 
def groups(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "intrusion-set" or o.get("revoked"):
            continue
        rows.append({
            "attack_id":   attack_id(o),
            "name":        o.get("name", ""),
            "aliases":     pipe(o.get("aliases", [])),
            "description": flat(o.get("description", "")),
            "created":     o.get("created", ""),
            "modified":    o.get("modified", ""),
            "stix_id":     o.get("id", ""),
            "url":         attack_url(o),
        })
    return rows
 
 
def malware(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "malware" or o.get("revoked"):
            continue
        rows.append({
            "attack_id":   attack_id(o),
            "name":        o.get("name", ""),
            "aliases":     pipe(o.get("x_mitre_aliases", [])),
            "platforms":   pipe(o.get("x_mitre_platforms", [])),
            "is_family":   o.get("is_family", ""),
            "description": flat(o.get("description", "")),
            "created":     o.get("created", ""),
            "modified":    o.get("modified", ""),
            "stix_id":     o.get("id", ""),
            "url":         attack_url(o),
        })
    return rows
 
 
def tools(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "tool" or o.get("revoked"):
            continue
        rows.append({
            "attack_id":   attack_id(o),
            "name":        o.get("name", ""),
            "aliases":     pipe(o.get("x_mitre_aliases", [])),
            "platforms":   pipe(o.get("x_mitre_platforms", [])),
            "description": flat(o.get("description", "")),
            "created":     o.get("created", ""),
            "modified":    o.get("modified", ""),
            "stix_id":     o.get("id", ""),
            "url":         attack_url(o),
        })
    return rows
 
 
def mitigations(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "course-of-action" or o.get("revoked"):
            continue
        rows.append({
            "attack_id":   attack_id(o),
            "name":        o.get("name", ""),
            "description": flat(o.get("description", "")),
            "created":     o.get("created", ""),
            "modified":    o.get("modified", ""),
            "stix_id":     o.get("id", ""),
            "url":         attack_url(o),
        })
    return rows
 
 
def relationships(objects: list) -> list:
    # Build id -> {name, type} lookup from all objects
    lookup = {o["id"]: {"name": o.get("name", ""), "type": o.get("type", "")}
              for o in objects if "id" in o}
    rows = []
    for o in objects:
        if o.get("type") != "relationship":
            continue
        src = lookup.get(o.get("source_ref", ""), {})
        tgt = lookup.get(o.get("target_ref", ""), {})
        rows.append({
            "relationship_type": o.get("relationship_type", ""),
            "source_stix_id":    o.get("source_ref", ""),
            "source_name":       src.get("name", ""),
            "source_type":       src.get("type", ""),
            "target_stix_id":    o.get("target_ref", ""),
            "target_name":       tgt.get("name", ""),
            "target_type":       tgt.get("type", ""),
            "description":       flat(o.get("description", "")),
            "created":           o.get("created", ""),
            "modified":          o.get("modified", ""),
            "stix_id":           o.get("id", ""),
        })
    return rows
 
 
def data_sources(objects: list) -> list:
    rows = []
    for o in objects:
        if o.get("type") != "x-mitre-data-source" or o.get("revoked"):
            continue
        rows.append({
            "attack_id":         attack_id(o),
            "name":              o.get("name", ""),
            "platforms":         pipe(o.get("x_mitre_platforms", [])),
            "collection_layers": pipe(o.get("x_mitre_collection_layers", [])),
            "description":       flat(o.get("description", "")),
            "created":           o.get("created", ""),
            "modified":          o.get("modified", ""),
            "stix_id":           o.get("id", ""),
            "url":               attack_url(o),
        })
    return rows
 
 
# Writer
 
def write_csv(rows: list, path: str):
    if not rows:
        print(f"  [skip] {Path(path).name}  (no data)")
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [ok]   {Path(path).name}  ({len(rows):,} rows)")
 
 
# Main
 
EXTRACTORS = {
    "techniques.csv":    techniques,
    "tactics.csv":       tactics,
    "groups.csv":        groups,
    "malware.csv":       malware,
    "tools.csv":         tools,
    "mitigations.csv":   mitigations,
    "relationships.csv": relationships,
    "data_sources.csv":  data_sources,
}
 
 
def convert(input_files: list, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
 
    # Load & merge all bundles
    all_objects = []
    for path in input_files:
        print(f"Loading  {path}")
        objs = load_bundle(path)
        print(f"         {len(objs):,} objects")
        all_objects.extend(objs)
 
    # Deduplicate by STIX id
    seen, unique = set(), []
    for o in all_objects:
        oid = o.get("id")
        if oid and oid not in seen:
            seen.add(oid)
            unique.append(o)
 
    print(f"\nUnique objects : {len(unique):,}")
    print(f"Output folder  : {output_dir}\n")
 
    for filename, extractor in EXTRACTORS.items():
        write_csv(extractor(unique), os.path.join(output_dir, filename))
 
    print("\nDone.")
 
 
if __name__ == "__main__":
    missing = [f for f in INPUT_FILES if not os.path.exists(f)]
    if missing:
        sys.exit(f"File(s) not found: {', '.join(missing)}")
 
    convert(INPUT_FILES, OUTPUT_DIR)