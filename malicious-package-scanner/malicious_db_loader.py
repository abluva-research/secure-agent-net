#!/usr/bin/env python3
import os
import json
import sys

# Get script directory (absolute path)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DIR = os.path.join(SCRIPT_DIR, "malicious-packages/osv/malicious")
OUT = os.path.join(SCRIPT_DIR, "data/malicious_index.json")

def load_malicious_index():
    """Load malicious packages into index with progress messaging"""
    idx = {}
    total_files = 0
    processed_files = 0
    
    print(f"[*] Using malicious packages from: {MAL_DIR}", file=sys.stderr)
    
    # Count total files first
    for eco in os.listdir(MAL_DIR):
        p = os.path.join(MAL_DIR, eco)
        if not os.path.isdir(p):
            continue
        for f in os.listdir(p):
            full_path = os.path.join(p, f)
            if os.path.isfile(full_path) and f.endswith(".json"):
                total_files += 1
    
    print(f"[*] Indexing {total_files} malicious package definitions...", file=sys.stderr)
    
    for eco in os.listdir(MAL_DIR):
        p = os.path.join(MAL_DIR, eco)
        if not os.path.isdir(p):
            continue
        
        if eco not in idx:
            idx[eco] = {}
        
        for f in os.listdir(p):
            full_path = os.path.join(p, f)
            
            # SKIP if it's a directory (not a file)
            if not os.path.isfile(full_path):
                continue
            
            # SKIP if not a JSON file
            if not f.endswith(".json"):
                continue
            
            processed_files += 1
            # Show progress every 10 files
            if processed_files % 10 == 0:
                pct = (processed_files / total_files) * 100 if total_files > 0 else 0
                print(f"[*] Indexing progress: {processed_files}/{total_files} ({pct:.0f}%)", file=sys.stderr)
            
            try:
                with open(full_path, 'r', encoding='utf-8') as fp:
                    d = json.load(fp)
                    
                    # Extract package name from affected field
                    for a in d.get("affected", []):
                        pkg = a.get("package", {})
                        name = pkg.get("name")
                        
                        if name:
                            # Store package in correct ecosystem
                            if eco not in idx:
                                idx[eco] = {}
                            idx[eco][name] = True
                            
            except json.JSONDecodeError as e:
                print(f"[!] JSON decode error in {f}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"[!] Error processing {f}: {e}", file=sys.stderr)
    
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as fp:
        json.dump(idx, fp, indent=2)
    
    total_packages = sum(len(v) for v in idx.values())
    print(f"[+] Index built successfully: {total_packages} malicious packages indexed", file=sys.stderr)
    
    # Show breakdown by ecosystem
    for eco in sorted(idx.keys()):
        count = len(idx[eco])
        if count > 0:
            print(f"    {eco}: {count} packages", file=sys.stderr)

if __name__ == "__main__":
    if not os.path.isdir(MAL_DIR):
        print(f"[!] Error: Malicious packages directory not found at {MAL_DIR}", file=sys.stderr)
        sys.exit(1)
    
    load_malicious_index()
