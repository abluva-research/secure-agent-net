#!/usr/bin/env python3
import os
import json
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DIR = os.path.join(SCRIPT_DIR, "malicious-packages", "osv", "malicious")
OUT = os.path.join(SCRIPT_DIR, "data", "malicious_index.json")

def load_malicious_index():
    if not os.path.isdir(MAL_DIR):
        print(f"[!] Malicious packages not found at {MAL_DIR}", file=sys.stderr)
        return False
    
    idx = {}
    total_files = 0
    processed_files = 0
    
    print(f"[*] Using malicious packages from: {MAL_DIR}", file=sys.stderr)
    
    try:
        for root, dirs, files in os.walk(MAL_DIR):
            for f in files:
                if f.endswith(".json"):
                    total_files += 1
    except Exception as e:
        print(f"[!] Error counting files: {e}", file=sys.stderr)
        return False
    
    if total_files == 0:
        print(f"[!] No JSON files found in {MAL_DIR}", file=sys.stderr)
        return False
    
    print(f"[*] Indexing {total_files} malicious package definitions...", file=sys.stderr)
    
    try:
        for root, dirs, files in os.walk(MAL_DIR):
            for f in files:
                if not f.endswith(".json"):
                    continue
                
                processed_files += 1
                if processed_files % 100 == 0:
                    pct = (processed_files / total_files) * 100 if total_files > 0 else 0
                    print(f"[*] Indexing progress: {processed_files}/{total_files} ({pct:.0f}%)", file=sys.stderr)
                
                full_path = os.path.join(root, f)
                
                try:
                    with open(full_path, 'r', encoding='utf-8') as fp:
                        d = json.load(fp)
                        
                        for a in d.get("affected", []):
                            pkg = a.get("package", {})
                            name = pkg.get("name")
                            
                            path_parts = root.split(os.sep)
                            ecosystem = None
                            
                            for i, part in enumerate(path_parts):
                                if part == "malicious" and i + 1 < len(path_parts):
                                    ecosystem = path_parts[i + 1]
                                    break
                            
                            if name and ecosystem:
                                if ecosystem not in idx:
                                    idx[ecosystem] = {}
                                idx[ecosystem][name] = True
                                
                except json.JSONDecodeError as e:
                    print(f"[!] JSON decode error in {f}: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"[!] Error processing {f}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Error scanning directories: {e}", file=sys.stderr)
        return False
    
    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
    except Exception as e:
        print(f"[!] Error creating data directory: {e}", file=sys.stderr)
        return False
    
    try:
        with open(OUT, 'w') as fp:
            json.dump(idx, fp, indent=2)
    except Exception as e:
        print(f"[!] Error writing index file: {e}", file=sys.stderr)
        return False
    
    total_packages = sum(len(v) for v in idx.values())
    print(f"[+] Index built successfully: {total_packages} malicious packages indexed", file=sys.stderr)
    
    for eco in sorted(idx.keys()):
        count = len(idx[eco])
        if count > 0:
            print(f"    {eco}: {count} packages", file=sys.stderr)
    
    return True

if __name__ == "__main__":
    success = load_malicious_index()
    sys.exit(0 if success else 1)
