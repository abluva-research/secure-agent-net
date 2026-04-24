#!/usr/bin/env python3
import sys, json, requests
from datetime import datetime
from difflib import SequenceMatcher

with open("data/malicious_index.json") as f:
    MAL_DB = json.load(f)

POPULAR = ["requests","flask","django","lodash","react","express"]

def sim(a,b): return SequenceMatcher(None,a,b).ratio()

def score(risks):
    s=0
    for r in risks:
        if r["type"]=="MALICIOUS_KNOWN": s+=100
        elif r["type"]=="TYPOSQUAT": s+=40
        elif r["type"]=="NEW_PACKAGE": s+=20
        elif r["type"]=="LOW_MAINTAINER_COUNT": s+=15
        elif r["type"]=="LOW_POPULARITY": s+=10
    return min(s,100)

pkg=sys.argv[1]
eco=sys.argv[2]

res={"package":pkg,"ecosystem":eco,"risks":[]}

if eco in MAL_DB and pkg in MAL_DB[eco]:
    res["risks"].append({"type":"MALICIOUS_KNOWN"})

for legit in POPULAR:
    if sim(pkg,legit)>0.8 and pkg!=legit:
        res["risks"].append({"type":"TYPOSQUAT","target":legit})

try:
    if eco=="pypi":
        r=requests.get(f"https://pypi.org/pypi/{pkg}/json",timeout=3)
        if r.status_code==200:
            data=r.json()
            rel=data.get("releases",{})
            if rel:
                first=list(rel.keys())[0]
                t=rel[first][0]["upload_time_iso_8601"]
                age=(datetime.utcnow()-datetime.fromisoformat(t.replace("Z",""))).days
                if age<7:
                    res["risks"].append({"type":"NEW_PACKAGE"})
    elif eco=="npm":
        r=requests.get(f"https://registry.npmjs.org/{pkg}",timeout=3)
        if r.status_code==200:
            data=r.json()
            if len(data.get("versions",{}))<5:
                res["risks"].append({"type":"LOW_POPULARITY"})
except:
    pass

res["risk_score"]=score(res["risks"])
print(json.dumps(res))
