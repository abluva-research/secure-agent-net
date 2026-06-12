#!/usr/bin/env python3
"""
OSV Dataset Manager
Manages caching, updating, and querying OSV vulnerability database locally
"""

import os
import json
import sys
import gzip
import tarfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import hashlib

class OSVDatasetManager:
    """Manages local OSV vulnerability dataset"""
    
    def __init__(self, cache_dir: str):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.meta_file = self.cache_dir / ".meta.json"
        self.index_file = self.cache_dir / "index.json"
        self.vulns_dir = self.cache_dir / "vulns"
        self.vulns_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict:
        """Load cache metadata"""
        if self.meta_file.exists():
            try:
                with open(self.meta_file) as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {
            "version": "1.0",
            "created_at": datetime.now().isoformat(),
            "last_updated": None,
            "datasets": {}
        }
    
    def _save_metadata(self):
        """Save cache metadata"""
        with open(self.meta_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def cache_query(self, purl: str, vulns: List[Dict]) -> str:
        """Cache OSV query results"""
        purl_hash = hashlib.sha256(purl.encode()).hexdigest()[:12]
        cache_file = self.vulns_dir / f"{purl_hash}.json"
        
        cache_data = {
            "purl": purl,
            "cached_at": datetime.now().isoformat(),
            "vulns": vulns,
            "vuln_count": len(vulns)
        }
        
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        return str(cache_file)
    
    def get_cached_query(self, purl: str, max_age_hours: int = 24) -> Optional[List[Dict]]:
        """Retrieve cached query results if valid"""
        purl_hash = hashlib.sha256(purl.encode()).hexdigest()[:12]
        cache_file = self.vulns_dir / f"{purl_hash}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file) as f:
                cache_data = json.load(f)
            
            cached_at = datetime.fromisoformat(cache_data["cached_at"])
            age_hours = (datetime.now() - cached_at).total_seconds() / 3600
            
            if age_hours <= max_age_hours:
                return cache_data["vulns"]
        except Exception:
            pass
        
        return None
    
    def list_cached_queries(self) -> List[Dict]:
        """List all cached vulnerability queries"""
        results = []
        
        for cache_file in self.vulns_dir.glob("*.json"):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                results.append({
                    "purl": data["purl"],
                    "cached_at": data["cached_at"],
                    "vuln_count": data["vuln_count"],
                    "file": str(cache_file)
                })
            except Exception:
                pass
        
        return sorted(results, key=lambda x: x["cached_at"], reverse=True)
    
    def clear_old_cache(self, max_age_hours: int = 168):
        """Clear cache older than max_age_hours"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        cleared = 0
        
        for cache_file in self.vulns_dir.glob("*.json"):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                cached_at = datetime.fromisoformat(data["cached_at"])
                
                if cached_at < cutoff:
                    cache_file.unlink()
                    cleared += 1
            except Exception:
                pass
        
        return cleared
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        cache_files = list(self.vulns_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        return {
            "total_cached_queries": len(cache_files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "cache_dir": str(self.cache_dir),
            "last_updated": self.metadata.get("last_updated")
        }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="OSV Dataset Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show cache statistics")
    stats_parser.add_argument("--cache-dir", default="./osv-data", help="Cache directory")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List cached queries")
    list_parser.add_argument("--cache-dir", default="./osv-data", help="Cache directory")
    list_parser.add_argument("--limit", type=int, default=10, help="Limit results")
    
    # Clear command
    clear_parser = subparsers.add_parser("clear", help="Clear old cache")
    clear_parser.add_argument("--cache-dir", default="./osv-data", help="Cache directory")
    clear_parser.add_argument("--older-than", type=int, default=168, help="Clear cache older than N hours")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    manager = OSVDatasetManager(args.cache_dir)
    
    if args.command == "stats":
        stats = manager.get_cache_stats()
        print("\nOSV Cache Statistics:")
        print(f"  Cached Queries: {stats['total_cached_queries']}")
        print(f"  Total Size: {stats['total_size_mb']} MB")
        print(f"  Cache Dir: {stats['cache_dir']}")
        if stats['last_updated']:
            print(f"  Last Updated: {stats['last_updated']}")
    
    elif args.command == "list":
        queries = manager.list_cached_queries()[:args.limit]
        print("\nCached Vulnerability Queries:")
        for i, q in enumerate(queries, 1):
            print(f"\n  {i}. {q['purl']}")
            print(f"     Cached: {q['cached_at']}")
            print(f"     Vulnerabilities: {q['vuln_count']}")
    
    elif args.command == "clear":
        cleared = manager.clear_old_cache(args.older_than)
        print(f"\nCleared {cleared} cache entries older than {args.older_than} hours")

if __name__ == "__main__":
    main()
