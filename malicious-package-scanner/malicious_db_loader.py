#!/usr/bin/env python3
import os
import json
import sys

# Get script directory (absolute path)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DIR = os.path.join(SCRIPT_DIR, "malicious-packages", "osv", "malicious")
OUT = os.path.join(SCRIPT_DIR, "data", "malicious_index.json")

def load_malicious_index():
    """Load malicious packages into index with progress messaging"""
    
    # Check if malicious packages directory exists
    if not os.path.isdir(MAL_DIR):
        print(f"[!] Malicious packages not found at {MAL_DIR}", file=sys.stderr)
        print(f"[!] Run this command first to clone the dataset:", file=sys.stderr)
        print(f"[!] cd {SCRIPT_DIR}", file=sys.stderr)
        print(f"[!] git clone https://github.com/ossf/malicious-packages", file=sys.stderr)
        return False
    
    idx = {}
    total_files = 0
    processed_files = 0
    
    print(f"[*] Using malicious packages from: {MAL_DIR}", file=sys.stderr)
    
    # Count total files first
    try:
        for eco in os.listdir(MAL_DIR):
            p = os.path.join(MAL_DIR, eco)
            if not os.path.isdir(p):
                continue
            for f in os.listdir(p):
                full_path = os.path.join(p, f)
                if os.path.isfile(full_path) and f.endswith(".json"):
                    total_files += 1
    except Exception as e:
        print(f"[!] Error counting files: {e}", file=sys.stderr)
        return False
    
    if total_files == 0:
        print(f"[!] No JSON files found in {MAL_DIR}", file=sys.stderr)
        return False
    
    print(f"[*] Indexing {total_files} malicious package definitions...", file=sys.stderr)
    
    try:
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
    except Exception as e:
        print(f"[!] Error scanning directories: {e}", file=sys.stderr)
        return False
    
    # Create data directory
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
    except Exception as e:
        print(f"[!] Error creating data directory: {e}", file=sys.stderr)
        return False
    
    # Write index
    try:
        with open(OUT, 'w') as fp:
            json.dump(idx, fp, indent=2)
    except Exception as e:
        print(f"[!] Error writing index file: {e}", file=sys.stderr)
        return False
    
    total_packages = sum(len(v) for v in idx.values())
    print(f"[+] Index built successfully: {total_packages} malicious packages indexed", file=sys.stderr)
    
    # Show breakdown by ecosystem
    for eco in sorted(idx.keys()):
        count = len(idx[eco])
        if count > 0:
            print(f"    {eco}: {count} packages", file=sys.stderr)
    
    return True

if __name__ == "__main__":
    success = load_malicious_index()
    sys.exit(0 if success else 1)
