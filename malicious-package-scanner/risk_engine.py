#!/usr/bin/env python3
import sys
import json
import requests
from datetime import datetime
from difflib import SequenceMatcher
import os

# Get script directory for relative paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DB_PATH = os.path.join(SCRIPT_DIR, "data", "malicious_index.json")

# Load malicious database
try:
    with open(MAL_DB_PATH) as f:
        MAL_DB = json.load(f)
except FileNotFoundError:
    MAL_DB = {}

POPULAR = ["requests", "flask", "django", "lodash", "react", "express"]


def sim(a, b):
    return SequenceMatcher(None, a, b).ratio()


def score(risks):
    s = 0
    for r in risks:
        if r["type"] == "MALICIOUS_KNOWN":
            s += 100
        elif r["type"] == "TYPOSQUAT":
            s += 40
        elif r["type"] == "NEW_PACKAGE":
            s += 20
        elif r["type"] == "LOW_MAINTAINER_COUNT":
            s += 15
        elif r["type"] == "LOW_POPULARITY":
            s += 10
    return min(s, 100)


def analyze_package(pkg, eco):
    """Analyze a single package and return risk data"""
    res = {"package": pkg, "ecosystem": eco, "risks": []}

    # Check if package is known malicious
    if eco in MAL_DB and pkg in MAL_DB[eco]:
        res["risks"].append({"type": "MALICIOUS_KNOWN"})

    # Check for typosquatting
    for legit in POPULAR:
        if sim(pkg, legit) > 0.8 and pkg != legit:
            res["risks"].append({"type": "TYPOSQUAT", "target": legit})

    # Check registry for additional risk factors
    try:
        if eco == "pypi":
            r = requests.get(
                f"https://pypi.org/pypi/{pkg}/json",
                timeout=3
            )
            if r.status_code == 200:
                data = r.json()
                rel = data.get("releases", {})
                if rel:
                    first = list(rel.keys())[0]
                    t = rel[first][0]["upload_time_iso_8601"]
                    age = (
                        datetime.utcnow() -
                        datetime.fromisoformat(t.replace("Z", ""))
                    ).days
                    if age < 7:
                        res["risks"].append({"type": "NEW_PACKAGE"})
        elif eco == "npm":
            r = requests.get(
                f"https://registry.npmjs.org/{pkg}",
                timeout=3
            )
            if r.status_code == 200:
                data = r.json()
                if len(data.get("versions", {})) < 5:
                    res["risks"].append({"type": "LOW_POPULARITY"})
    except Exception:
        pass

    res["risk_score"] = score(res["risks"])
    return res


def format_terminal_output(result):
    """Format result for terminal display (single package)"""
    pkg = result["package"]
    score = result["risk_score"]
    risks = result["risks"]

    # Color codes
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

    # Determine status
    if score == 0:
        status = f"{GREEN}✅ SAFE{NC}"
        status_text = "No risks found"
    elif score < 50:
        status = f"{YELLOW}⚠️  CAUTION{NC}"
        status_text = "Some suspicious indicators"
    elif score < 80:
        status = f"{YELLOW}⚠️⚠️ HIGH RISK{NC}"
        status_text = "Multiple risk factors detected"
    else:
        status = f"{RED}🚨 CRITICAL{NC}"
        status_text = "Known malicious or very suspicious"

    # Print output
    print(f"\n{BLUE}{'='*50}{NC}")
    print(f"{BLUE}Package Analysis Result{NC}")
    print(f"{BLUE}{'='*50}{NC}\n")
    print(f"Package:     {pkg}")
    print(f"Ecosystem:   {result['ecosystem']}")
    print(f"Status:      {status}")
    print(f"Risk Score:  {score}/100")
    print(f"Details:     {status_text}\n")

    if risks:
        print(f"{BLUE}Detected Risks:{NC}")
        for i, risk in enumerate(risks, 1):
            risk_type = risk["type"]
            if risk_type == "MALICIOUS_KNOWN":
                print(f"  {i}. {RED}MALICIOUS_KNOWN{NC} - Package is known to be malicious")
            elif risk_type == "TYPOSQUAT":
                target = risk.get("target", "unknown")
                print(f"  {i}. {YELLOW}TYPOSQUAT{NC} - Looks like '{target}'")
            elif risk_type == "NEW_PACKAGE":
                print(f"  {i}. {YELLOW}NEW_PACKAGE{NC} - Published less than 7 days ago")
            elif risk_type == "LOW_POPULARITY":
                print(f"  {i}. {YELLOW}LOW_POPULARITY{NC} - Very few versions")
            elif risk_type == "LOW_MAINTAINER_COUNT":
                print(f"  {i}. {YELLOW}LOW_MAINTAINER{NC} - Few maintainers")
    else:
        print(f"{GREEN}No risks detected{NC}\n")

    print(f"{BLUE}{'='*50}{NC}\n")

    return score


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: risk_engine.py <package> <ecosystem>", file=sys.stderr)
        sys.exit(1)

    pkg = sys.argv[1]
    eco = sys.argv[2]

    result = analyze_package(pkg, eco)
    
    # Check if running in single package mode (from command line)
    if len(sys.argv) == 4 and sys.argv[3] == "--terminal":
        # Terminal output mode (for single package check)
        risk_score = format_terminal_output(result)
        sys.exit(0 if risk_score < 80 else 1)
    else:
        # JSON output mode (for SBOM scanning)
        print(json.dumps(result))
        sys.exit(0)