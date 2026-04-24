import os,json
MAL_DIR="./malicious-packages/osv/malicious"
OUT="./data/malicious_index.json"
idx={}
for eco in os.listdir(MAL_DIR):
    p=os.path.join(MAL_DIR,eco)
    if not os.path.isdir(p): continue
    idx[eco]={}
    for f in os.listdir(p):
        if f.endswith(".json"):
            try:
                d=json.load(open(os.path.join(p,f)))
                for a in d.get("affected",[]):
                    name=a.get("package",{}).get("name")
                    if name: idx[eco][name]=True
            except: pass
os.makedirs("data",exist_ok=True)
json.dump(idx,open(OUT,"w"),indent=2)
print("[+] index built")
