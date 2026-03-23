
#!/usr/bin/env bash
# ============================================================
# Kubernetes Security Scanner v1.0
# ============================================================

set -euo pipefail

# ==============================
# Globals
# ==============================
SCRIPT_START_TIME=$(date +%s)
SCAN_DATE=$(date +"%d-%b-%Y_%H-%M")
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_ID=""

OUTPUT_ROOT=""
RUN_DIR=""
TMP_KUBECONFIG=""
IAC_DIR=""
NAMESPACE=""
ENABLE_ACTIVE_SCAN="N"
CREATE_REPORT="Y"

# Per-scanner timing
declare -A SCANNER_START
declare -A SCANNER_DURATION

# Raw output files
KUBE_HUNTER_PASSIVE_JSON=""
KUBE_HUNTER_ACTIVE_JSON=""
KUBE_BENCH_JSON=""
TERRASCAN_JSON=""
RBAC_FILE=""
SECRETS_FILE=""
NETWORK_FILE=""

# ==============================
# Logging
# ==============================
log_info()  { echo -e "\e[34m[i]\e[0m $*"; }
log_good()  { echo -e "\e[32m[+]\e[0m $*"; }
log_warn()  { echo -e "\e[33m[WARN]\e[0m $*"; }
log_error() { echo -e "\e[31m[ERR]\e[0m $*"; }

# ==============================
# Timer helpers
# ==============================
timer_start() { SCANNER_START[$1]=$(date +%s); }
timer_end() {
    local name=$1
    local end
    end=$(date +%s)
    SCANNER_DURATION[$name]=$(( end - SCANNER_START[$name] ))
}

# ==============================
# Format HH:MM:SS
# ==============================
format_duration() {
    local t=$1
    printf "%02d:%02d:%02d" $((t/3600)) $(( (t%3600)/60 )) $((t%60))
}

# ==============================
# Dependency check
# ==============================
check_dependencies() {
    local missing=0
    for cmd in docker kubectl jq python3; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "$cmd is required but not installed"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

# ==============================
# Cleanup
# ==============================
cleanup() {
    if [[ -n "$TMP_KUBECONFIG" && -f "$TMP_KUBECONFIG" ]]; then
        rm -f "$TMP_KUBECONFIG" || true
    fi
    local containers
    containers=$(docker ps -q --filter "label=k8s-scan-temp" 2>/dev/null) || true
    if [[ -n "$containers" ]]; then
        docker rm -f $containers >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ==============================
# safe_jq -- variadic --arg fix
# ==============================
safe_jq() {
    local file="$1"
    local filter="$2"
    shift 2
    if [[ -s "$file" ]]; then
        jq -c "$@" "$filter" "$file" 2>/dev/null || echo "[]"
    else
        echo "[]"
    fi
}

# ==============================
# Interactive setup
# ==============================
interactive_setup() {
    echo ""
    echo "============================================"
    echo "   Kubernetes Security Scanner v3.0"
    echo "============================================"
    echo ""

    # --- Output directory ---
    read -rp "Output dir (default ./scans): " OUTPUT_ROOT || true
    OUTPUT_ROOT=${OUTPUT_ROOT:-./scans}

    # --- Namespace ---
    read -rp "Namespace to scan (default: all): " NAMESPACE || true
    NAMESPACE=${NAMESPACE:-all}

    # --- YAML / IaC dir ---
    echo ""
    echo "YAML / IaC folder to scan for security misconfigurations:"
    echo "  Terrascan will scan Kubernetes YAML manifests, Helm charts,"
    echo "  Terraform, and Dockerfiles found in this directory."
    read -rp "Enter path (default: current dir): " IAC_DIR || true
    IAC_DIR=${IAC_DIR:-$PWD}
    IAC_DIR=$(realpath -m "$IAC_DIR")
    if [[ ! -d "$IAC_DIR" ]]; then
        log_warn "Directory '$IAC_DIR' does not exist — using current dir instead"
        IAC_DIR=$PWD
    fi
    log_info "YAML/IaC path: $IAC_DIR"

    # --- Dir naming ---
    # Default format: scan_<namespace>_DD-Mon-YYYY_HH-MM
    # Custom format:  scan-<name>-DD-Mon-YYYY_HH-MM
    echo ""
    echo "Dir naming:"
    echo "  1) default   scan_${NAMESPACE}_${SCAN_DATE}"
    echo "  2) custom    scan-<yourname>-${SCAN_DATE}"
    read -rp "Select [1]: " DIR_STYLE || true
    DIR_STYLE=${DIR_STYLE:-1}

    if [[ "$DIR_STYLE" == "2" ]]; then
        read -rp "Enter scan name (letters, numbers, hyphens only): " CUSTOM_NAME || true
        CUSTOM_NAME=$(echo "$CUSTOM_NAME" | tr ' /' '--' | tr -cd '[:alnum:]-')
        if [[ -z "$CUSTOM_NAME" ]]; then
            log_warn "Empty name given, using namespace as name"
            CUSTOM_NAME="$NAMESPACE"
        fi
        RUN_DIR="$(realpath -m "$OUTPUT_ROOT")/scan-${CUSTOM_NAME}-${SCAN_DATE}"
    else
        RUN_DIR="$(realpath -m "$OUTPUT_ROOT")/scan_${NAMESPACE}_${SCAN_DATE}"
    fi

    SCAN_ID=$(basename "$RUN_DIR")
    mkdir -p "$RUN_DIR" "$RUN_DIR/sbom" "$RUN_DIR/logs" "$RUN_DIR/scan-results"

    # --- Active scan warning ---
    echo ""
    echo "WARNING: Active scanning is intrusive."
    echo "   Performs real attack simulations, may trigger IDS/IPS,"
    echo "   and can cause production incidents."
    echo "   Use ONLY in staging or with explicit approval."
    echo ""
    read -rp "Enable kube-hunter ACTIVE scan? (y/N): " ENABLE_ACTIVE_SCAN || true
    ENABLE_ACTIVE_SCAN=${ENABLE_ACTIVE_SCAN:-N}

    # --- Report output ---
    read -rp "Generate master report + HTML? (Y/n): " CREATE_REPORT || true
    CREATE_REPORT=${CREATE_REPORT:-Y}

    # --- Auth ---
    echo ""
    echo "Auth method:"
    echo "  1) Use existing kubeconfig"
    echo "  2) API server + Token"
    read -rp "Select [1]: " AUTH_METHOD || true
    AUTH_METHOD=${AUTH_METHOD:-1}

    if [[ "$AUTH_METHOD" == "2" ]]; then
        read -rp "API Server URL: " API_SERVER || true
        read -rp "Token: " TOKEN || true
        TMP_KUBECONFIG=$(mktemp)
        cat > "$TMP_KUBECONFIG" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: $API_SERVER
    insecure-skip-tls-verify: true
  name: tmp
contexts:
- context:
    cluster: tmp
    user: tmp
  name: tmp
current-context: tmp
users:
- name: tmp
  user:
    token: $TOKEN
EOF
        export KUBECONFIG="$TMP_KUBECONFIG"
    fi

    kubectl get ns >/dev/null 2>&1 || { log_error "Cluster access failed -- check kubeconfig/token"; exit 1; }

    log_good "Cluster access confirmed"
    log_info "Scan ID   : $SCAN_ID"
    log_info "Namespace : $NAMESPACE"
    log_info "Output    : $RUN_DIR"
    echo ""
}

# ==============================
# Scanners
# ==============================

run_kube_hunter() {
    log_good "Running kube-hunter..."
    timer_start "kube_hunter"

    local KUBE_CONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
    if [[ ! -f "$KUBE_CONFIG_PATH" ]]; then
        log_error "Kubeconfig not found at $KUBE_CONFIG_PATH"
        SCANNER_DURATION[kube_hunter]=0
        return 1
    fi

    KUBE_HUNTER_PASSIVE_JSON="$RUN_DIR/scan-results/kube-hunter-passive.json"
    docker run --rm \
        --net host \
        -v "$KUBE_CONFIG_PATH:/root/.kube/config:ro" \
        aquasec/kube-hunter \
        --kubeconfig /root/.kube/config \
        --k8s-auto-discover-nodes \
        --report json \
        > "$KUBE_HUNTER_PASSIVE_JSON" \
        2> "$RUN_DIR/logs/kube-hunter-passive.log"
    log_info "Passive scan done"

    if [[ "$ENABLE_ACTIVE_SCAN" =~ ^[Yy]$ ]]; then
        log_warn "Running ACTIVE scan..."
        KUBE_HUNTER_ACTIVE_JSON="$RUN_DIR/scan-results/kube-hunter-active.json"
        docker run --rm \
            --net host \
            -v "$KUBE_CONFIG_PATH:/root/.kube/config:ro" \
            aquasec/kube-hunter \
            --kubeconfig /root/.kube/config \
            --k8s-auto-discover-nodes \
            --active \
            --report json \
            > "$KUBE_HUNTER_ACTIVE_JSON" \
            2> "$RUN_DIR/logs/kube-hunter-active.log"
        log_info "Active scan done"
    else
        log_info "Active scan skipped"
        KUBE_HUNTER_ACTIVE_JSON=""
    fi

    timer_end "kube_hunter"
}

run_kube_bench() {
    log_good "Running kube-bench (CIS benchmark)..."
    timer_start "kube_bench"

    KUBE_BENCH_JSON="$RUN_DIR/scan-results/kube-bench.json"
    docker run --rm -t \
        --net host \
        --pid host \
        -v /var:/var:ro \
        aquasec/kube-bench \
        --json > "$KUBE_BENCH_JSON" 2> "$RUN_DIR/logs/kube-bench.log"

    timer_end "kube_bench"
    log_info "kube-bench done"
}

run_terrascan() {
    log_good "Running terrascan (IaC)..."
    timer_start "terrascan"

    TERRASCAN_JSON="$RUN_DIR/scan-results/terrascan.json"
    docker run --rm \
        -v "$IAC_DIR":/iac \
        tenable/terrascan \
        scan -d /iac -o json --use-colors f \
        > "$TERRASCAN_JSON" 2> "$RUN_DIR/logs/terrascan.log" || true

    # Strip any residual ANSI codes / carriage returns terrascan may inject
    if [[ -s "$TERRASCAN_JSON" ]]; then
        python3 -c "
import sys, re
with open(sys.argv[1], 'r', errors='replace') as f:
    data = f.read()
data = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', data)
data = data.replace('\r', '')
with open(sys.argv[1], 'w') as f:
    f.write(data)
" "$TERRASCAN_JSON" || true
    fi

    timer_end "terrascan"
    log_info "terrascan done"
}

run_syft_grype() {
    log_good "Running SBOM + vulnerability scan..."
    timer_start "syft_grype"

    local IMAGES
    # Use spec.containers[*].image + spec.initContainers[*].image scoped to namespace only
    # Avoids picking up images from other namespaces via broad {..image} jsonpath
    if [[ "$NAMESPACE" == "all" ]]; then
        IMAGES=$(kubectl get pods -A \
            -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
            | sort -u | grep -v '^$')
    else
        IMAGES=$(kubectl get pods -n "$NAMESPACE" \
            -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
            | sort -u | grep -v '^$')
    fi

    local IMAGE_LIST=()
    while IFS= read -r img; do
        [[ -n "$img" ]] && IMAGE_LIST+=("$img")
    done <<< "$IMAGES"

    local TOTAL=${#IMAGE_LIST[@]}
    log_info "  Found $TOTAL images — scanning up to 4 in parallel"

    # Per-image scan function (runs in subshell via &)
    _scan_image() {
        local IMAGE="$1"
        local IDX="$2"
        local SAFE_IMAGE
        SAFE_IMAGE=$(echo "$IMAGE" | sed 's#[/:]#_#g')
        local SBOM_FILE="$RUN_DIR/sbom/sbom-${SAFE_IMAGE}.json"
        local VULN_FILE="$RUN_DIR/sbom/sbom-vuln-${SAFE_IMAGE}.json"
        local SYFT_LOG="$RUN_DIR/logs/syft-${SAFE_IMAGE}.log"
        local GRYPE_LOG="$RUN_DIR/logs/grype-${SAFE_IMAGE}.log"

        local DOCKER_CONFIG_MOUNT=()
        if [[ -f "$HOME/.docker/config.json" ]]; then
            DOCKER_CONFIG_MOUNT=(-v "$HOME/.docker/config.json:/root/.docker/config.json:ro")
        fi

        echo "[${IDX}/${TOTAL}] Syft: $IMAGE"
        if ! docker run --rm \
            "${DOCKER_CONFIG_MOUNT[@]}" \
            -e SYFT_REGISTRY_INSECURE_USE_HTTP=true \
            -e SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true \
            anchore/syft "$IMAGE" -o json \
            > "$SBOM_FILE" 2>"$SYFT_LOG"; then
            echo "[WARN] Syft failed for $IMAGE"
            head -3 "$SYFT_LOG" 2>/dev/null || true
            rm -f "$SBOM_FILE"
            return
        fi

        # Validate SBOM is a non-empty valid JSON before calling Grype
        if [[ ! -s "$SBOM_FILE" ]] || ! python3 -c "import sys,json; json.load(open(sys.argv[1]))" "$SBOM_FILE" 2>/dev/null; then
            echo "[WARN] Syft produced invalid/empty SBOM for $IMAGE — skipping Grype"
            cat "$SYFT_LOG" | head -5 2>/dev/null || true
            rm -f "$SBOM_FILE"
            return
        fi

        echo "[${IDX}/${TOTAL}] Grype: $IMAGE"
        if ! docker run --rm \
            -v "$RUN_DIR":/workdir \
            anchore/grype "sbom:/workdir/sbom/sbom-${SAFE_IMAGE}.json" \
            -o json \
            > "$VULN_FILE" 2>"$GRYPE_LOG"; then
            echo "[WARN] Grype failed for $IMAGE"
            head -3 "$GRYPE_LOG" 2>/dev/null || true
        fi
    }
    export -f _scan_image
    export RUN_DIR TOTAL HOME

    # Parallel with max 4 concurrent jobs
    local PARALLEL=4
    local PIDS=()

    for i in "${!IMAGE_LIST[@]}"; do
        local IDX=$((i + 1))
        _scan_image "${IMAGE_LIST[$i]}" "$IDX" &
        PIDS+=($!)

        if [[ ${#PIDS[@]} -ge $PARALLEL ]]; then
            wait "${PIDS[0]}" || true
            PIDS=("${PIDS[@]:1}")
        fi
    done

    # Wait for remaining jobs
    for pid in "${PIDS[@]}"; do
        wait "$pid" || true
    done

    timer_end "syft_grype"
    log_good "syft+grype done (${#IMAGE_LIST[@]} images)"
}

run_k8s_checks() {
    log_good "Running RBAC / Secrets / Network checks..."
    timer_start "k8s_checks"

    local SAFE_NS
    SAFE_NS=$(echo "$NAMESPACE" | tr -cd '[:alnum:]_-' | cut -c1-40)

    if [[ "$NAMESPACE" == "all" ]]; then
        RBAC_FILE="$RUN_DIR/scan-results/rbac.json"
        SECRETS_FILE="$RUN_DIR/scan-results/secrets.json"
        NETWORK_FILE="$RUN_DIR/scan-results/network.json"
        kubectl get roles,rolebindings -A -o json    > "$RBAC_FILE"
        kubectl get secrets -A -o json               > "$SECRETS_FILE"
        kubectl get networkpolicy -A -o json         > "$NETWORK_FILE"
    else
        RBAC_FILE="$RUN_DIR/scan-results/${SAFE_NS}-rbac.json"
        SECRETS_FILE="$RUN_DIR/scan-results/${SAFE_NS}-secrets.json"
        NETWORK_FILE="$RUN_DIR/scan-results/${SAFE_NS}-network.json"
        kubectl get roles,rolebindings -n "$NAMESPACE" -o json > "$RBAC_FILE"
        kubectl get secrets -n "$NAMESPACE" -o json            > "$SECRETS_FILE"
        kubectl get networkpolicy -n "$NAMESPACE" -o json      > "$NETWORK_FILE"
    fi

    timer_end "k8s_checks"
    log_info "k8s checks done"
}

# ============================================================
# build_master_report
# Produces:
#   master-report.json  -- enriched nested JSON
#     .meta             -- scan identity, timing
#     .summary          -- stat-panel-ready counts (Grafana/dashboards)
#     .scanners.*       -- full lossless findings per scanner
#   <scan_id>.html      -- self-contained HTML with JSON download
# ============================================================
build_master_report() {
    if [[ ! "$CREATE_REPORT" =~ ^[Yy]$ ]]; then
        return
    fi

    log_good "Building enriched master report..."

    local SCAN_END_TIME
    SCAN_END_TIME=$(date +%s)
    local TOTAL_DURATION=$(( SCAN_END_TIME - SCRIPT_START_TIME ))
    local MASTER_FILE="$RUN_DIR/master-report.json"
    local HTML_FILE="$RUN_DIR/${SCAN_ID}.html"

    python3 - \
        "$RUN_DIR" \
        "$SCAN_ID" \
        "$SCAN_TIMESTAMP" \
        "$NAMESPACE" \
        "$TOTAL_DURATION" \
        "${SCANNER_DURATION[kube_bench]:-0}" \
        "${SCANNER_DURATION[kube_hunter]:-0}" \
        "${SCANNER_DURATION[terrascan]:-0}" \
        "${SCANNER_DURATION[syft_grype]:-0}" \
        "${SCANNER_DURATION[k8s_checks]:-0}" \
        "$KUBE_HUNTER_PASSIVE_JSON" \
        "${KUBE_HUNTER_ACTIVE_JSON:-}" \
        "$KUBE_BENCH_JSON" \
        "$TERRASCAN_JSON" \
        "$RBAC_FILE" \
        "$NETWORK_FILE" \
        "$SECRETS_FILE" \
        "$MASTER_FILE" \
        "$HTML_FILE" \
        <<'PYEOF'

import json, os, glob, sys, html as html_mod

(run_dir, scan_id, scan_ts, namespace,
 total_dur, kb_dur, kh_dur, ts_dur, sg_dur, k8_dur,
 kh_passive_path, kh_active_path, kb_path, ts_path,
 rbac_path, net_path, sec_path,
 master_path, html_path) = sys.argv[1:]

total_dur = int(total_dur); kb_dur = int(kb_dur); kh_dur = int(kh_dur)
ts_dur = int(ts_dur); sg_dur = int(sg_dur); k8_dur = int(k8_dur)

def load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            raw = f.read().strip()
        if raw and raw[0] not in ('{', '['):
            for ch in ('{', '['):
                idx = raw.find(ch)
                if idx != -1:
                    raw = raw[idx:]
                    break
        return json.loads(raw)
    except Exception as e:
        print(f"[WARN] Could not parse {path}: {e}", file=sys.stderr)
        return None

def h(s):
    return html_mod.escape(str(s) if s is not None else "")

def parse_kube_hunter(path, mode):
    data = load_json(path)
    if not data:
        return {
            "status": "no_data" if path else "skipped",
            "mode": mode, "duration_seconds": kh_dur,
            "nodes": [], "services": [], "vulnerabilities": [],
            "summary": {"nodes": 0, "services": 0, "vulnerabilities": 0}
        }
    vulns = []
    for v in data.get("vulnerabilities", []):
        vulns.append({
            "id":          v.get("vulnerability_id", ""),
            "name":        v.get("vulnerability", ""),
            "severity":    v.get("severity", ""),
            "description": v.get("description", ""),
            "evidence":    v.get("evidence", ""),
            "resource":    v.get("resource", ""),
            "location":    v.get("location", ""),
            "category":    v.get("category", ""),
            "remediation": v.get("remediation", ""),
            "reference":   v.get("reference", ""),
        })
    return {
        "status": "ok", "mode": mode, "duration_seconds": kh_dur,
        "summary": {
            "nodes":           len(data.get("nodes", [])),
            "services":        len(data.get("services", [])),
            "vulnerabilities": len(vulns),
        },
        "nodes":           data.get("nodes", []),
        "services":        data.get("services", []),
        "vulnerabilities": vulns,
    }

def parse_kube_bench(path):
    data = load_json(path)
    if not data:
        return {"status": "no_data", "duration_seconds": kb_dur,
                "cis_version": "", "sections": [],
                "summary": {"pass": 0, "fail": 0, "warn": 0, "total": 0, "score_pct": 0}}
    sections = []
    tp = tf = tw = 0
    cis_ver = ""
    for ctrl in data.get("Controls", []):
        cis_ver = ctrl.get("version", "")
        p = ctrl.get("total_pass", 0)
        f = ctrl.get("total_fail", 0)
        w = ctrl.get("total_warn", 0)
        tp += p; tf += f; tw += w
        findings = []
        for grp in ctrl.get("tests", []):
            for res in grp.get("results", []):
                findings.append({
                    "test_number": res.get("test_number", ""),
                    "description": res.get("test_desc", ""),
                    "status":      res.get("status", ""),
                    "scored":      res.get("scored", True),
                    "remediation": str(res.get("remediation") or "").strip(),
                    "reason":      res.get("reason", ""),
                    "audit":       res.get("audit", ""),
                    "expected":    res.get("expected_result", ""),
                    "actual":      res.get("actual_value", ""),
                })
        sections.append({
            "id": ctrl.get("id", ""), "title": ctrl.get("text", ""),
            "node_type": ctrl.get("node_type", ""),
            "pass": p, "fail": f, "warn": w,
            "findings": findings,
        })
    total = tp + tf + tw
    score = round(tp / total * 100, 1) if total else 0
    return {
        "status": "ok", "duration_seconds": kb_dur,
        "cis_version": cis_ver,
        "summary": {"pass": tp, "fail": tf, "warn": tw, "total": total, "score_pct": score},
        "sections": sections,
    }

def parse_terrascan(path):
    data = load_json(path)
    if not data:
        return {"status": "no_data", "duration_seconds": ts_dur,
                "violations": [], "scan_errors": [],
                "summary": {"policies_validated": 0, "violated_policies": 0,
                            "high": 0, "medium": 0, "low": 0}}
    results  = data.get("results", {})
    raw_v    = results.get("violations") or []
    scan_sum = results.get("scan_summary") or {}
    violations = []
    for v in raw_v:
        violations.append({
            "rule_name":      v.get("rule_name", ""),
            "description":    v.get("description", ""),
            "severity":       v.get("severity", ""),
            "category":       v.get("category", ""),
            "resource_name":  v.get("resource_name", ""),
            "resource_type":  v.get("resource_type", ""),
            "file":           v.get("file", ""),
            "line":           v.get("line") or 0,
            "iac_type":       v.get("iac_type", ""),
            "remediation":    v.get("fix", ""),
            "reference_link": v.get("reference_link", ""),
        })
    return {
        "status": "ok", "duration_seconds": ts_dur,
        "scan_summary": scan_sum,
        "scan_errors":  results.get("scan_errors") or [],
        "summary": {
            "policies_validated": scan_sum.get("policies_validated", 0),
            "violated_policies":  scan_sum.get("violated_policies", 0),
            "high":   scan_sum.get("high", 0),
            "medium": scan_sum.get("medium", 0),
            "low":    scan_sum.get("low", 0),
        },
        "violations": violations,
    }

def _safe_licenses(raw):
    """Extract license strings safely from any Syft license format."""
    result = set()
    for l in (raw or []):
        try:
            if isinstance(l, str):
                v = l.strip()
            elif isinstance(l, dict):
                v = str(l.get("value","") or l.get("spdxExpression","") or l.get("name","") or "").strip()
            else:
                v = str(l).strip()
            if v and not v.startswith("{") and not v.startswith("[") and len(v) < 100:
                result.add(v)
        except Exception:
            pass
    return sorted(result)

def parse_syft_grype():
    vuln_index = {}
    for vf in glob.glob(os.path.join(run_dir, "sbom", "sbom-vuln-*.json")):
        key = os.path.basename(vf).replace("sbom-vuln-", "").replace(".json", "")
        vuln_index[key] = vf

    sev_totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
    total_findings = 0
    images_list = []

    for sf in glob.glob(os.path.join(run_dir, "sbom", "sbom-*.json")):
        base = os.path.basename(sf)
        if "sbom-vuln-" in base:
            continue
        key = base.replace("sbom-", "").replace(".json", "")
        sbom_data = load_json(sf)
        packages = []
        pkg_types = {}
        if sbom_data:
            for art in sbom_data.get("artifacts", []):
                t = art.get("type", "unknown")
                pkg_types[t] = pkg_types.get(t, 0) + 1
                packages.append({
                    "name":    art.get("name", ""),
                    "version": art.get("version", ""),
                    "type":    t,
                    "purl":    art.get("purl", ""),
                    "licenses": _safe_licenses(art.get("licenses")),
                })
        findings = []
        img_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
        if key in vuln_index:
            gd = load_json(vuln_index[key])
            if gd:
                for m in gd.get("matches", []):
                    vuln = m.get("vulnerability", {})
                    art  = m.get("artifact", {})
                    sev  = vuln.get("severity", "Unknown")
                    fix  = vuln.get("fix", {})
                    cvss_list = vuln.get("cvss") or []
                    cvss_score = None
                    if cvss_list:
                        cvss_score = cvss_list[0].get("metrics", {}).get("baseScore")
                    finding = {
                        "id":           vuln.get("id", ""),
                        "severity":     sev,
                        "cvss_score":   cvss_score,
                        "description":  vuln.get("description", ""),
                        "package":      art.get("name", ""),
                        "version":      art.get("version", ""),
                        "package_type": art.get("type", ""),
                        "purl":         art.get("purl", ""),
                        "fix_available":fix.get("state", "") == "fixed",
                        "fix_state":    fix.get("state", "unknown"),
                        "fix_versions": fix.get("versions", []),
                        "urls":         vuln.get("urls", []),
                        "related_ids":  [r.get("id","") for r in vuln.get("relatedVulnerabilities", [])],
                        "namespace":    vuln.get("namespace", ""),
                        "data_source":  vuln.get("dataSource", ""),
                    }
                    findings.append(finding)
                    total_findings += 1
                    if sev in img_sev:
                        img_sev[sev] += 1
                    if sev in sev_totals:
                        sev_totals[sev] += 1

        # Recover image name from SBOM source metadata (most reliable)
        image_name = key  # fallback
        if sbom_data:
            src = sbom_data.get("source", {})
            src_meta = src.get("metadata", {})
            user_input = src_meta.get("userInput", "")
            if user_input:
                image_name = user_input
            elif src.get("name"):
                img_n = src.get("name","")
                img_v = src.get("version","")
                image_name = f"{img_n}:{img_v}" if img_v else img_n
        images_list.append({
            "image":                 image_name,
            "safe_key":              key,
            "package_count":         len(packages),
            "package_types":         pkg_types,
            "packages":              packages,
            "vulnerability_summary": img_sev,
            "vulnerabilities":       findings,
        })

    return {
        "status": "ok", "duration_seconds": sg_dur,
        "images_scanned": len(images_list),
        "summary": {**sev_totals, "total": total_findings},
        "images": images_list,
    }

def parse_rbac(path):
    data = load_json(path)
    if not data:
        return {"status": "no_data", "duration_seconds": k8_dur,
                "roles": [], "role_bindings": [],
                "summary": {"roles": 0, "role_bindings": 0,
                            "roles_with_secret_access": 0,
                            "roles_with_sensitive_verbs": 0}}
    roles, bindings = [], []
    for item in (data.get("items") or []):
        kind = item.get("kind", "")
        meta = item.get("metadata", {})
        if kind == "Role":
            rules = [{"api_groups": r.get("apiGroups") or [],
                      "resources":  r.get("resources") or [],
                      "verbs":      r.get("verbs") or []}
                     for r in (item.get("rules") or [])]
            sensitive = any(
                v in ("*", "create", "delete", "update", "patch")
                for rule in (item.get("rules") or []) for v in (rule.get("verbs") or [])
            )
            secret_access = any(
                "secrets" in (rule.get("resources") or [])
                for rule in (item.get("rules") or [])
            )
            roles.append({
                "name": meta.get("name", ""), "namespace": meta.get("namespace", ""),
                "created": meta.get("creationTimestamp", ""), "uid": meta.get("uid", ""),
                "rules": rules,
                "sensitive_verbs": sensitive,
                "secret_access":   secret_access,
            })
        elif kind == "RoleBinding":
            bindings.append({
                "name": meta.get("name", ""), "namespace": meta.get("namespace", ""),
                "created": meta.get("creationTimestamp", ""), "uid": meta.get("uid", ""),
                "role_ref": item.get("roleRef") or {},
                "subjects": [{"kind": s.get("kind", ""), "name": s.get("name", ""),
                               "namespace": s.get("namespace", "")}
                              for s in (item.get("subjects") or [])],
            })
    return {
        "status": "ok", "duration_seconds": k8_dur,
        "summary": {
            "roles":                       len(roles),
            "role_bindings":               len(bindings),
            "roles_with_secret_access":    sum(1 for r in roles if r["secret_access"]),
            "roles_with_sensitive_verbs":  sum(1 for r in roles if r["sensitive_verbs"]),
        },
        "roles": roles, "role_bindings": bindings,
    }

def parse_network(path):
    data = load_json(path)
    if not data:
        return {"status": "no_data", "duration_seconds": k8_dur,
                "policies": [],
                "summary": {"total_policies": 0, "no_policies_warn": True}}
    policies = []
    for item in (data.get("items") or []):
        meta = item.get("metadata") or {}
        spec = item.get("spec") or {}
        policies.append({
            "name":          meta.get("name", ""),
            "namespace":     meta.get("namespace", ""),
            "created":       meta.get("creationTimestamp", ""),
            "pod_selector":  spec.get("podSelector") or {},
            "ingress_rules": len(spec.get("ingress") or []),
            "egress_rules":  len(spec.get("egress") or []),
            "policy_types":  spec.get("policyTypes") or [],
        })
    return {
        "status": "ok", "duration_seconds": k8_dur,
        "summary": {"total_policies": len(policies),
                    "no_policies_warn": len(policies) == 0},
        "policies": policies,
    }

def parse_secrets(path):
    data = load_json(path)
    if not data:
        return {"status": "no_data", "duration_seconds": k8_dur,
                "secrets": [], "summary": {"total": 0, "by_type": {}}}
    secrets = []
    type_count = {}
    for item in (data.get("items") or []):
        meta = item.get("metadata") or {}
        t    = item.get("type", "Opaque")
        type_count[t] = type_count.get(t, 0) + 1
        secrets.append({
            "name":      meta.get("name", ""),
            "namespace": meta.get("namespace", ""),
            "type":      t,
            "created":   meta.get("creationTimestamp", ""),
            "key_count": len(item.get("data") or {}),
        })
    return {
        "status": "ok", "duration_seconds": k8_dur,
        "summary": {"total": len(secrets), "by_type": type_count},
        "secrets": secrets,
    }

# ── Parse all scanners ───────────────────────────────────────────────
kh_passive = parse_kube_hunter(kh_passive_path, "passive")
kh_active  = parse_kube_hunter(kh_active_path, "active") if kh_active_path else \
             {"status": "skipped", "mode": "active"}
kb  = parse_kube_bench(kb_path)
ts  = parse_terrascan(ts_path)
sg  = parse_syft_grype()
rb  = parse_rbac(rbac_path)
net = parse_network(net_path)
sec = parse_secrets(sec_path)

vs  = sg["summary"]
cis = kb["summary"]

# ── Assemble master report ───────────────────────────────────────────
report = {
    "meta": {
        "scan_id":   scan_id,
        "timestamp": scan_ts,
        "scan_date": scan_ts[:10],
        "namespace": namespace,
        "scanner_versions": {
            "kube_hunter": "aquasec/kube-hunter:latest",
            "kube_bench":  "aquasec/kube-bench:latest",
            "terrascan":   "tenable/terrascan:latest",
            "syft":        "anchore/syft:latest",
            "grype":       "anchore/grype:latest",
        },
        "scanner_durations": {
            "kube_hunter_seconds": kh_dur,
            "kube_bench_seconds":  kb_dur,
            "terrascan_seconds":   ts_dur,
            "syft_grype_seconds":  sg_dur,
            "k8s_checks_seconds":  k8_dur,
            "total_seconds":       total_dur,
        },
    },
    "summary": {
        "vulnerabilities": {
            "critical":       vs.get("Critical", 0),
            "high":           vs.get("High", 0),
            "medium":         vs.get("Medium", 0),
            "low":            vs.get("Low", 0),
            "negligible":     vs.get("Negligible", 0),
            "total":          vs.get("total", 0),
            "images_scanned": sg["images_scanned"],
        },
        "cis_benchmark": {
            "pass":        cis.get("pass", 0),
            "fail":        cis.get("fail", 0),
            "warn":        cis.get("warn", 0),
            "total":       cis.get("total", 0),
            "score_pct":   cis.get("score_pct", 0),
            "cis_version": kb.get("cis_version", ""),
        },
        "cluster": {
            "nodes":             len(kh_passive.get("nodes", [])),
            "exposed_services":  len(kh_passive.get("services", [])),
            "network_policies":  net["summary"].get("total_policies", 0),
            "no_network_policy": net["summary"].get("no_policies_warn", True),
            "secrets_total":     sec["summary"].get("total", 0),
            "rbac_roles":        rb["summary"].get("roles", 0),
            "rbac_bindings":     rb["summary"].get("role_bindings", 0),
            "rbac_secret_access":rb["summary"].get("roles_with_secret_access", 0),
        },
        "iac": {
            "policies_validated": ts["summary"].get("policies_validated", 0),
            "violated_policies":  ts["summary"].get("violated_policies", 0),
            "high":   ts["summary"].get("high", 0),
            "medium": ts["summary"].get("medium", 0),
            "low":    ts["summary"].get("low", 0),
        },
        "packages": {
            "total": sum(i["package_count"] for i in sg.get("images", [])),
        },
    },
    "scanners": {
        "kube_hunter_passive": kh_passive,
        "kube_hunter_active":  kh_active,
        "kube_bench":          kb,
        "terrascan":           ts,
        "syft_grype":          sg,
        "rbac":                rb,
        "network_policies":    net,
        "secrets":             sec,
    },
}

# ── Write master-report.json ─────────────────────────────────────────
with open(master_path, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(f"[+] master-report.json -> {master_path}")
print(f"    CVEs      : {vs.get('total',0)} total  "
      f"C:{vs.get('Critical',0)} H:{vs.get('High',0)} "
      f"M:{vs.get('Medium',0)} L:{vs.get('Low',0)}")
print(f"    CIS Score : {cis.get('score_pct',0)}%  "
      f"({cis.get('pass',0)}P / {cis.get('fail',0)}F / {cis.get('warn',0)}W)")
print(f"    Net Policy: {net['summary'].get('total_policies',0)}")
print(f"    RBAC Roles: {rb['summary'].get('roles',0)}")

# ── Build HTML report ────────────────────────────────────────────────
sc      = report["scanners"]
summary = report["summary"]
meta_d  = report["meta"]
vs2     = summary["vulnerabilities"]
cis2    = summary["cis_benchmark"]
cl      = summary["cluster"]
iac     = summary["iac"]

sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Negligible":4,"Unknown":5}

# ── Per-image SBOM panels (vulns + licenses merged) ──
sbom_img_panels = ""
for img in sc.get("syft_grype", {}).get("images", []):
    img_name  = img.get("image", img.get("safe_key",""))
    img_short = img_name.split("/")[-1] if "/" in img_name else img_name
    pkg_cnt   = img.get("package_count", 0)
    img_sev   = img.get("vulnerability_summary", {})
    vuln_list = sorted(img.get("vulnerabilities", []),
                       key=lambda x: sev_order.get(x.get("severity","Unknown"), 5))

    # build per-package license lookup
    pkg_lic = {}
    for pkg in img.get("packages", []):
        lics = _safe_licenses(pkg.get("licenses"))
        pkg_name_key = pkg.get("name","")
        if isinstance(pkg_name_key, dict): pkg_name_key = str(pkg_name_key.get("name",""))
        pkg_name_key = str(pkg_name_key).strip()
        if lics and pkg_name_key:
            pkg_lic[pkg_name_key] = ", ".join(lics)

    rows = ""
    for v in vuln_list:
        sev      = h(str(v.get("severity") or ""))
        pkg_name = str(v.get("package") or "")
        pkg_ver  = str(v.get("version") or "")
        pkg_type = str(v.get("package_type") or "")
        raw_lic  = pkg_lic.get(pkg_name, "")
        lic_val  = h(str(raw_lic)) if raw_lic else "—"
        is_cp    = any(x in lic_val.upper() for x in ["GPL","LGPL","AGPL","MPL","EUPL","CDDL"])
        lic_cls  = "sev High" if is_cp else "sev Low" if lic_val != "—" else ""
        lic_html = f'<span class="{lic_cls}">{lic_val}</span>' if lic_cls else f'<span style="color:var(--muted)">{lic_val}</span>'
        raw_urls = v.get("urls") or []
        urls     = [str(u) for u in raw_urls if isinstance(u, str)] if raw_urls else []
        url_html = " ".join(
            f'<a href="{h(u)}" target="_blank" class="ref-link">{h(u[:45])}</a>'
            for u in urls[:1]
        ) if urls else "—"
        fix_cls  = "fixed" if v.get("fix_available") else "unfixed"
        fix_lbl  = h(str(v.get("fix_state") or "unknown"))
        raw_fv   = v.get("fix_versions") or []
        fix_vers = h(str(raw_fv[0])) if raw_fv else "—"
        cvss     = v.get("cvss_score")
        cvss_html = f'<span style="font-weight:500">{cvss}</span>' if cvss else "—"
        vid = h(str(v.get("id") or ""))
        rows += (
            f'<tr style="border-left:3px solid '
            + ('var(--crit)' if sev=="Critical" else 'var(--high)' if sev=="High" else 'var(--med)' if sev=="Medium" else 'var(--low)')
            + f'">' 
            f'<td class="mono" style="font-size:10px">{vid}</td>'
            f'<td><span class="sev {sev}">{sev}</span></td>'
            f'<td>{h(pkg_name)}</td>'
            f'<td class="mono" style="font-size:10px">{h(pkg_ver)}</td>'
            f'<td class="mono" style="font-size:10px">{h(pkg_type)}</td>'
            f'<td>{lic_html}</td>'
            f'<td>{cvss_html}</td>'
            f'<td><span class="fix {fix_cls}">{fix_lbl}</span></td>'
            f'<td class="mono" style="font-size:10px">{fix_vers}</td>'
            f'<td style="font-size:10px">{url_html}</td>'
            f'</tr>'
        )

    sev_badges = " ".join(
        f'<span class="sev {s}">{img_sev.get(s,0)} {s}</span>'
        for s in ["Critical","High","Medium","Low"] if img_sev.get(s,0) > 0
    ) or '<span style="color:var(--low)">No vulnerabilities</span>'

    sbom_img_panels += f'''<div class="panel">
    <div class="panel-head">
      <div class="panel-title" title="{h(img_name)}">{h(img_short)}</div>
      <div style="display:flex;align-items:center;gap:6px">{sev_badges}<span style="font-size:11px;color:var(--muted)">{pkg_cnt} pkgs</span></div>
    </div>'''
    if rows:
        sbom_img_panels += f'''
    <div class="tw"><table>
      <thead><tr><th>CVE / GHSA</th><th>Severity</th><th>Package</th><th>Version</th><th>Type</th><th>License</th><th>CVSS</th><th>Fix state</th><th>Fix version</th><th>Ref</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>'''
    else:
        sbom_img_panels += '<div style="padding:10px 16px;color:var(--low);font-size:12px">No vulnerabilities found for this image.</div>'
    sbom_img_panels += '</div>'

vuln_rows = ""  # kept for backward compat

cis_rows = ""
for sec_item in sc.get("kube_bench", {}).get("sections", []):
    for f in sec_item.get("findings", []):
        if f.get("status") != "FAIL":
            continue
        cis_rows += f"""<tr>
          <td class="mono">{h(f.get("test_number",""))}</td>
          <td><span class="sev FAIL">FAIL</span></td>
          <td style="color:var(--muted);font-size:12px">{h(sec_item.get("title",""))}</td>
          <td>{h(f.get("description",""))}</td>
          <td style="font-size:11px;color:var(--muted)">{h(f.get("remediation","")[:220])}</td>
        </tr>"""

rbac_rows = ""
for role in sc.get("rbac", {}).get("roles", []):
    flags = ""
    if role.get("secret_access"):
        flags += '<span class="sev High">secret access</span> '
    if role.get("sensitive_verbs"):
        flags += '<span class="sev Medium">sensitive verbs</span>'
    rules_html = "<br>".join(
        f"{h(','.join(r.get('resources',[])))}: {h(','.join(r.get('verbs',[])))}"
        for r in role.get("rules", [])
    )
    rbac_rows += f"""<tr>
      <td class="mono">{h(role.get("name",""))}</td><td>Role</td>
      <td style="font-size:12px">{rules_html}</td><td>{flags}</td>
    </tr>"""
for rb_item in sc.get("rbac", {}).get("role_bindings", []):
    subj = ", ".join(s.get("name", "") for s in rb_item.get("subjects", []))
    rbac_rows += f"""<tr>
      <td class="mono">{h(rb_item.get("name",""))}</td><td>RoleBinding</td>
      <td style="font-size:12px">{h(subj)} -> {h(rb_item.get("role_ref",{}).get("name",""))}</td>
      <td>-</td>
    </tr>"""

svc_rows = "".join(f"""<tr>
  <td>{h(s.get("service",""))}</td>
  <td class="mono">{h(s.get("location",""))}</td>
  <td><span class="sev Medium">Exposed</span></td>
</tr>""" for s in sc.get("kube_hunter_passive", {}).get("services", []))

ts_err_rows = "".join(
    f'<tr><td class="mono">{h(e.get("iac_type",""))}</td>'
    f'<td style="color:var(--muted)">{h(e.get("errMsg",""))}</td></tr>'
    for e in sc.get("terrascan", {}).get("scan_errors", [])
)

def sev_class(s):
    s = (s or "").upper()
    return "c" if s == "CRITICAL" else "h" if s == "HIGH" else "m" if s == "MEDIUM" else "l" if s == "LOW" else "a"

def ts_row_color(s):
    s=(s or "").upper()
    if s=="HIGH": return "var(--high)"
    if s=="MEDIUM": return "var(--med)"
    if s=="LOW": return "var(--low)"
    return "var(--muted)"

ts_viol_rows = "".join(
    f'<tr style="border-left:3px solid {ts_row_color(v.get("severity"))}">'
    f'<td><span class="sev {h(v.get("severity","").title())}">{h(v.get("severity",""))}</span></td>'
    f'<td class="mono">{h(v.get("rule_name",""))}</td>'
    f'<td>{h(v.get("description",""))}</td>'
    f'<td class="mono">{h(v.get("resource_name",""))}</td>'
    f'<td class="mono">{h(v.get("file",""))}</td>'
    f'<td>{h(v.get("category",""))}</td>'
    f'</tr>'
    for v in sc.get("terrascan", {}).get("violations", [])
)
ts_has_viols = bool(sc.get("terrascan", {}).get("violations"))

# ── Secret rows ──
secret_rows = ""
for s in sc.get("secrets", {}).get("secrets", []):
    stype = h(s.get("type","Opaque"))
    sname = h(s.get("name",""))
    sns   = h(s.get("namespace",""))
    keys  = s.get("key_count", 0)
    created = h(s.get("created","")[:10])
    # Flag service account tokens and docker config secrets
    is_sensitive = any(x in s.get("type","") for x in ["kubernetes.io/tls","kubernetes.io/dockerconfigjson","kubernetes.io/service-account-token"])
    flag = '<span class="sev High">sensitive</span>' if is_sensitive else '<span class="sev Low">standard</span>'
    secret_rows += f'<tr><td class="mono">{sname}</td><td class="mono" style="font-size:11px">{sns}</td><td class="mono">{stype}</td><td style="text-align:right">{keys}</td><td>{flag}</td><td class="muted">{created}</td></tr>'

secrets_by_type = sc.get("secrets", {}).get("summary", {}).get("by_type", {})
secrets_type_rows = "".join(
    f'<tr><td class="mono">{h(t)}</td><td style="text-align:right">{c}</td></tr>'
    for t,c in sorted(secrets_by_type.items(), key=lambda x:-x[1])
)
total_secrets = sc.get("secrets", {}).get("summary", {}).get("total", 0)

# ── NetworkPolicy rows ──
netpol_rows = ""
for p in sc.get("network_policies", {}).get("policies", []):
    pname = h(p.get("name",""))
    pns   = h(p.get("namespace",""))
    ingress = p.get("ingress_rules", 0)
    egress  = p.get("egress_rules", 0)
    ptypes  = h(", ".join(p.get("policy_types", [])))
    netpol_rows += f'<tr><td class="mono">{pname}</td><td class="mono" style="font-size:11px">{pns}</td><td>{ptypes}</td><td style="text-align:right">{ingress}</td><td style="text-align:right">{egress}</td></tr>'

total_netpols = sc.get("network_policies", {}).get("summary", {}).get("total_policies", 0)
no_netpol     = sc.get("network_policies", {}).get("summary", {}).get("no_policies_warn", True)

license_rows = ""
license_summary = {}
for img in sc.get("syft_grype", {}).get("images", []):
    for pkg in img.get("packages", []):
        for lic in (pkg.get("licenses") or []):
            for l in _safe_licenses([lic]):
                license_summary[l] = license_summary.get(l, 0) + 1

for lic_name, count in sorted(license_summary.items(), key=lambda x: -x[1]):
    is_copyleft = any(x in lic_name.upper() for x in ["GPL","LGPL","AGPL","MPL","EUPL","CDDL"])
    risk_cls = "sev High" if is_copyleft else "sev Low"
    risk_lbl = "Copyleft" if is_copyleft else "Permissive"
    license_rows += f'<tr><td>{h(lic_name)}</td><td><span class="{risk_cls}">{risk_lbl}</span></td><td style="text-align:right">{count}</td></tr>'

total_license_pkgs = sum(license_summary.values())
copyleft_count = sum(v for k,v in license_summary.items() if any(x in k.upper() for x in ["GPL","LGPL","AGPL","MPL","EUPL","CDDL"]))

license_img_panels = ""
for img in sc.get("syft_grype", {}).get("images", []):
    img_nm   = h(img.get("image", img.get("safe_key","")))
    pkg_cnt  = img.get("package_count", 0)
    pkg_types_str = ", ".join(f"{v} {k}" for k,v in sorted(img.get("package_types",{}).items(), key=lambda x:-x[1]))
    # per-image license breakdown
    img_lic = {}
    for pkg in img.get("packages", []):
        for lic in (pkg.get("licenses") or []):
            for l in _safe_licenses([lic]):
                img_lic[l] = img_lic.get(l,0)+1
    img_lic_rows = "".join(
        f'<tr><td>{h(ln)}</td><td><span class="sev {"High" if any(x in ln.upper() for x in ["GPL","LGPL","AGPL","MPL","EUPL","CDDL"]) else "Low"}">{"Copyleft" if any(x in ln.upper() for x in ["GPL","LGPL","AGPL","MPL","EUPL","CDDL"]) else "Permissive"}</span></td><td style="text-align:right">{c}</td></tr>'
        for ln,c in sorted(img_lic.items(), key=lambda x:-x[1])
    )
    img_short = img_nm.split("/")[-1] if "/" in img_nm else img_nm
    license_img_panels += f'''<div class="panel">
    <div class="panel-head"><div class="panel-title" title="{img_nm}">{img_short}</div><div class="panel-badge">{pkg_cnt} packages · {pkg_types_str}</div></div>
    <div class="tw"><table>
      <thead><tr><th>License</th><th>Type</th><th style="text-align:right">Count</th></tr></thead>
      <tbody>{img_lic_rows if img_lic_rows else '<tr><td colspan="3" style="color:var(--muted)">No license data</td></tr>'}</tbody>
    </table></div>
  </div>'''

license_panel = ""
if license_rows:
    license_panel = (
        '<div class="panel">'
        '<div class="panel-head"><div class="panel-title">License breakdown</div>'
        '<div class="panel-badge">by package count</div></div>'
        '<div class="tw"><table>'
        '<thead><tr><th>License</th><th>Type</th><th style="text-align:right">Packages</th></tr></thead>'
        '<tbody>' + license_rows + '</tbody>'
        '</table></div></div>'
    )

ts_viol_panel = ""
if ts_has_viols:
    ts_viol_panel = (
        '<div class="panel">'
        '<div class="panel-head"><div class="panel-title">Violations</div></div>'
        '<div class="tw"><table>'
        '<thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Resource</th><th>File</th><th>Category</th></tr></thead>'
        '<tbody>' + ts_viol_rows + '</tbody>'
        '</table></div></div>'
    )

ts_err_panel = ""
if ts_err_rows:
    ts_err_panel = (
        '<div class="panel">'
        '<div class="panel-head"><div class="panel-title">Scan Errors</div></div>'
        '<div class="tw"><table>'
        '<thead><tr><th>IaC Type</th><th>Message</th></tr></thead>'
        '<tbody>' + ts_err_rows + '</tbody>'
        '</table></div></div>'
    )

score_pct   = cis2.get("score_pct", 0)
score_color = "#f74f4f" if score_pct < 50 else "#f7d24f" if score_pct < 75 else "#4ff7a0"

bench_bars = ""
for s in sc.get("kube_bench", {}).get("sections", []):
    total_s = s.get("pass", 0) + s.get("fail", 0) + s.get("warn", 0) or 1
    pp = round(s.get("pass", 0) / total_s * 100)
    pf = round(s.get("fail", 0) / total_s * 100)
    pw = 100 - pp - pf
    bench_bars += f"""<div class="prog-row">
      <div class="prog-label" title="{h(s.get('title',''))}">{h(s.get('id',''))}. {h(s.get('title',''))}</div>
      <div class="prog-track">
        <div class="prog-p" style="width:{pp}%"></div>
        <div class="prog-f" style="width:{pf}%"></div>
        <div class="prog-w" style="width:{pw}%"></div>
      </div>
      <div class="prog-nums">
        <span style="color:var(--pass)">{s.get('pass',0)}P</span>
        <span style="color:var(--crit)">{s.get('fail',0)}F</span>
        <span style="color:var(--med)">{s.get('warn',0)}W</span>
      </div>
    </div>"""

dur_rows = "".join(
    f'<div class="dur-row"><span style="color:var(--muted)">'
    f'{h(k.replace("_seconds","").replace("_"," "))}</span>'
    f'<span class="mono">{v}s</span></div>'
    for k, v in meta_d.get("scanner_durations", {}).items()
)

# ── Top actions for overview ──
top_actions = []
crit_fixable = [v for img in sc.get("syft_grype",{}).get("images",[]) for v in img.get("vulnerabilities",[]) if v.get("severity")=="Critical" and v.get("fix_available")]
if crit_fixable:
    v0 = crit_fixable[0]
    top_actions.append({"sev":"c","title":f"Patch {v0.get('package','')} (CVSS {v0.get('cvss_score','?')}, Critical)","sub":f"{v0.get('id','')} · fix: {(v0.get('fix_versions') or ['?'])[0]} · {len(crit_fixable)} critical CVE(s) fixable"})
etcd_fails = [f for sec in sc.get("kube_bench",{}).get("sections",[]) if sec.get("node_type")=="etcd" for f in sec.get("findings",[]) if f.get("status")=="FAIL"]
if etcd_fails:
    top_actions.append({"sev":"c","title":f"Fix Etcd TLS configuration ({len(etcd_fails)} CIS FAILs)","sub":"Etcd unauthenticated — entire cluster state potentially exposed"})
if cl.get("no_network_policy"):
    top_actions.append({"sev":"c","title":"Define NetworkPolicy for namespace","sub":"Zero policies defined — all pod-to-pod traffic unrestricted"})
rbac_secret = [r for r in sc.get("rbac",{}).get("roles",[]) if r.get("secret_access")]
if rbac_secret:
    top_actions.append({"sev":"h","title":f"Revoke secrets access on {rbac_secret[0].get('name','role')}","sub":f"{len(rbac_secret)} role(s) can get/list/create/delete secrets"})
worker_fails = sum(1 for sec in sc.get("kube_bench",{}).get("sections",[]) if sec.get("node_type")=="node" for f in sec.get("findings",[]) if f.get("status")=="FAIL")
if worker_fails:
    top_actions.append({"sev":"h","title":f"Remediate {worker_fails} worker node CIS failures","sub":"Includes kubelet anonymous auth, file permissions, audit logging"})
high_fixable = sum(1 for img in sc.get("syft_grype",{}).get("images",[]) for v in img.get("vulnerabilities",[]) if v.get("severity")=="High" and v.get("fix_available"))
if high_fixable:
    top_actions.append({"sev":"h","title":f"Update packages — {high_fixable} High CVEs have fixes available","sub":"Run npm/apk update in affected images"})
iac_high = sum(1 for v in sc.get("terrascan",{}).get("violations",[]) if (v.get("severity") or "").upper()=="HIGH")
if iac_high:
    top_actions.append({"sev":"h","title":f"Fix {iac_high} HIGH severity YAML misconfigurations","sub":"Privilege escalation, running as root, no security context"})

top_actions_html = "".join(
    f'<div class="top-action"><div class="action-num {a["sev"]}">{i+1}</div><div><div class="action-title">{h(a["title"])}</div><div class="action-sub">{h(a["sub"])}</div></div></div>'
    for i,a in enumerate(top_actions[:7])
) or '<div style="color:var(--muted);font-size:12px;padding:8px 0">No critical actions identified</div>'

# ── Heatmap helper ──
def hm_cell(val, warn_at=1, crit_at=5, label=""):
    if val == 0: cls="hm-g"
    elif crit_at > warn_at and val >= crit_at: cls="hm-r"
    else: cls="hm-a"
    return f'<div class="hm-cell {cls}"><span class="hm-n">{val}</span><span class="hm-l">{label}</span></div>'

nt_counts = {}
for sec in sc.get("kube_bench",{}).get("sections",[]):
    nt = sec.get("node_type","?")
    nt_counts.setdefault(nt, {"fail":0,"warn":0})
    nt_counts[nt]["fail"] += sec.get("fail",0)
    nt_counts[nt]["warn"] += sec.get("warn",0)

total_crit_h = vs2.get("critical",0)+vs2.get("high",0)
rbac_issues  = sum(1 for r in sc.get("rbac",{}).get("roles",[]) if r.get("secret_access") or r.get("sensitive_verbs"))
net_issues   = 1 if cl.get("no_network_policy") else 0
iac_issues   = sc.get("terrascan",{}).get("summary",{}).get("violated_policies",0)

# Pre-build all heatmap cells (can't call functions inside f-string with {{}} escaping)
hm_master_cis  = hm_cell(nt_counts.get("master",  {}).get("fail",0), 1, 5,  "fails")
hm_master_vuln = hm_cell(total_crit_h,                               1, 10, "C+H")
hm_master_rbac = hm_cell(rbac_issues,                                1, 3,  "issues")
hm_master_net  = hm_cell(net_issues,                                 1, 1,  "policies")
hm_master_iac  = hm_cell(iac_issues,                                 1, 10, "viols")
hm_etcd_cis    = hm_cell(nt_counts.get("etcd",    {}).get("fail",0), 1, 3,  "fails")
hm_worker_cis  = hm_cell(nt_counts.get("node",    {}).get("fail",0), 1, 5,  "fails")
hm_pol_cis     = hm_cell(nt_counts.get("policies",{}).get("warn",0), 1, 10, "warns")
hm_blank       = '<div class="hm-cell hm-n"><span class="hm-n">—</span></div>' 

svc_risk = {"Etcd":"crit","Kubelet API":"high","Unrecognized K8s API":"med","API server":"low"}
exposed_svc_rows = "".join(
    f'<div class="svc-row"><span>{h(s.get("service",""))}</span><span class="mono muted">{h(s.get("location",""))}</span><span class="sev {svc_risk.get(s.get("service",""),"Low").title()}">{svc_risk.get(s.get("service",""),"info")}</span></div>'
    for s in (sc.get("kube_hunter_passive") or {{}}).get("services",[])
) or '<div style="color:var(--muted);font-size:12px">No services discovered</div>'

total_scan_secs = meta_d.get("scanner_durations", {}).get("total_seconds", 0)

def _svc_cls(svc):
    if "Etcd" in svc: return "Critical"
    if "Kubelet" in svc: return "High"
    if "Unrecognized" in svc: return "Medium"
    return "Low"

svc_risk_rows = "".join(
    f'<tr><td>{h(str(s.get("service","")))}</td>'
    f'<td class="mono">{h(str(s.get("location","")))}</td>'
    f'<td><span class="sev {_svc_cls(str(s.get("service","")))}">{_svc_cls(str(s.get("service","")))}</span></td></tr>'
    for s in (sc.get("kube_hunter_passive") or {}).get("services", [])
)

net_warn_html = ""
if cl.get("no_network_policy"):
    net_warn_html = '<div class="alert-box">No NetworkPolicy objects found -- all pod-to-pod traffic is unrestricted.</div>'

json_blob = json.dumps(report, indent=2, default=str).replace("</", "<\\/")

html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>K8s Security Report - {h(meta_d.get("scan_id",""))}</title>
<style>
:root{{--bg:#0b0e14;--bg2:#12161f;--bg3:#1a1f2e;--border:#252c3d;--text:#c8d0e0;
  --muted:#5a6480;--accent:#4f8ef7;--crit:#f74f4f;--high:#f79a4f;--med:#f7d24f;
  --low:#4ff7a0;--pass:#4ff7a0;--mono:'Courier New',monospace;--sans:system-ui,sans-serif;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px}}
.shell{{display:grid;grid-template-columns:210px 1fr;min-height:100vh}}
.sidebar{{background:var(--bg2);border-right:1px solid var(--border);padding:24px 0;position:sticky;top:0;height:100vh;overflow-y:auto;overflow-x:visible}}
.main{{padding:32px 36px;overflow-x:hidden}}
.logo{{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}}
.logo-title{{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent);letter-spacing:.08em}}
.logo-sub{{font-size:11px;color:var(--muted);margin-top:3px}}
.nav-sec{{padding:14px 20px 5px;font-size:10px;font-family:var(--mono);color:var(--muted);letter-spacing:.12em;text-transform:uppercase}}
.nav-info{{margin-left:auto;font-size:11px;color:var(--muted);cursor:help;user-select:none;flex-shrink:0}}
#nav-tooltip{{position:fixed;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:7px 11px;font-size:11px;color:var(--text);max-width:240px;white-space:normal;line-height:1.5;z-index:9999;pointer-events:none;display:none}}
.nav-item{{display:flex;align-items:center;gap:9px;padding:8px 20px;cursor:pointer;font-size:13px;color:var(--muted);border-left:2px solid transparent;transition:all .15s}}
.nav-item:hover{{color:var(--text);background:var(--bg3)}}
.nav-item.active{{color:var(--accent);border-left-color:var(--accent);background:rgba(79,142,247,.07)}}
.nav-dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0}}
.section{{display:none}}.section.active{{display:block}}
.page-title{{font-family:var(--mono);font-size:18px;font-weight:700;color:#fff;margin-bottom:4px}}
.page-sub{{font-size:12px;color:var(--muted);margin-bottom:24px}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px 18px;position:relative;overflow:hidden}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
.stat.c::before{{background:var(--crit)}}.stat.h::before{{background:var(--high)}}
.stat.m::before{{background:var(--med)}}.stat.l::before{{background:var(--low)}}
.stat.p::before{{background:var(--pass)}}.stat.a::before{{background:var(--accent)}}
.stat-label{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-family:var(--mono)}}
.stat-value{{font-family:var(--mono);font-size:28px;font-weight:700;margin:4px 0 2px}}
.stat.c .stat-value{{color:var(--crit)}}.stat.h .stat-value{{color:var(--high)}}
.stat.m .stat-value{{color:var(--med)}}.stat.l .stat-value{{color:var(--low)}}
.stat.p .stat-value{{color:var(--pass)}}.stat.a .stat-value{{color:var(--accent)}}
.stat-hint{{font-size:11px;color:var(--muted)}}
.panel{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}}
.panel-head{{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}}
.panel-title{{font-family:var(--mono);font-size:12px;font-weight:700;color:#fff}}
.panel-badge{{font-family:var(--mono);font-size:10px;background:var(--bg3);padding:2px 8px;border-radius:3px;color:var(--muted)}}
.tw{{max-height:440px;overflow-y:auto}}
.tw::-webkit-scrollbar{{width:4px}}.tw::-webkit-scrollbar-thumb{{background:var(--border);border-radius:2px}}
table{{width:100%;border-collapse:collapse}}
th{{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);padding:9px 16px;text-align:left;background:var(--bg3);border-bottom:1px solid var(--border)}}
td{{padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(255,255,255,.015)}}
.mono{{font-family:var(--mono);font-size:12px}}
.sev{{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px}}
.sev.Critical{{background:rgba(247,79,79,.15);color:var(--crit);border:1px solid rgba(247,79,79,.3)}}
.sev.High{{background:rgba(247,154,79,.15);color:var(--high);border:1px solid rgba(247,154,79,.3)}}
.sev.Medium{{background:rgba(247,210,79,.15);color:var(--med);border:1px solid rgba(247,210,79,.3)}}
.sev.Low{{background:rgba(79,247,160,.1);color:var(--low);border:1px solid rgba(79,247,160,.25)}}
.sev.FAIL{{background:rgba(247,79,79,.15);color:var(--crit);border:1px solid rgba(247,79,79,.3)}}
.fix{{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:3px}}
.fix.fixed{{background:rgba(79,247,160,.1);color:var(--low);border:1px solid rgba(79,247,160,.25)}}
.fix.unfixed{{background:rgba(247,79,79,.1);color:var(--crit);border:1px solid rgba(247,79,79,.25)}}
.ref-link{{color:var(--accent);font-size:11px;word-break:break-all}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:16px 18px}}
.meta-row{{display:flex;flex-direction:column;gap:3px}}
.meta-key{{font-size:10px;font-family:var(--mono);color:var(--muted);text-transform:uppercase}}
.meta-val{{font-size:13px}}
.top-action{{display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-bottom:1px solid var(--border)}}
.top-action:last-child{{border-bottom:none}}
.action-num{{width:20px;height:20px;border-radius:50%;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}}
.action-num.c{{background:rgba(247,79,79,.15);color:var(--crit)}}
.action-num.h{{background:rgba(247,154,79,.15);color:var(--high)}}
.action-title{{font-size:12px;font-weight:500;color:var(--text)}}
.action-sub{{font-size:11px;color:var(--muted);margin-top:2px}}
.top-actions-wrap{{padding:4px 0}}
.heatmap-grid{{display:grid;grid-template-columns:64px repeat(5,1fr);gap:3px;font-size:10px}}
.hm-head{{padding:3px;color:var(--muted);text-align:center;font-size:10px}}
.hm-row{{padding:3px 4px;color:var(--muted);font-size:10px;display:flex;align-items:center}}
.hm-cell{{border-radius:4px;padding:4px 2px;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:32px}}
.hm-n{{font-size:13px;font-weight:500}}
.hm-l{{font-size:9px;margin-top:1px}}
.hm-r{{background:rgba(247,79,79,.15)}}.hm-r .hm-n{{color:var(--crit)}}.hm-r .hm-l{{color:var(--crit)}}
.hm-a{{background:rgba(247,154,79,.12)}}.hm-a .hm-n{{color:var(--high)}}.hm-a .hm-l{{color:var(--high)}}
.hm-g{{background:rgba(79,247,160,.1)}}.hm-g .hm-n{{color:var(--low)}}.hm-g .hm-l{{color:var(--low)}}
.hm-n-cell{{background:var(--bg3)}}.hm-n-cell .hm-n{{color:var(--muted)}}
.svc-list{{display:flex;flex-direction:column;gap:0}}
.svc-row{{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px}}
.svc-row:last-child{{border-bottom:none}}
.dl-btn{{font-family:var(--mono);font-size:11px;padding:6px 14px;border-radius:4px;border:1px solid var(--accent);background:rgba(79,142,247,.1);color:var(--accent);cursor:pointer;text-decoration:none;display:inline-block;margin-bottom:16px}}
.dl-btn:hover{{background:rgba(79,142,247,.2)}}
.alert-box{{background:rgba(247,79,79,.1);border:1px solid rgba(247,79,79,.3);border-radius:6px;padding:12px 16px;color:var(--crit);font-size:13px;margin:16px 18px}}
.prog-row{{display:flex;align-items:center;gap:10px;padding:11px 18px;border-bottom:1px solid var(--border)}}
.prog-row:last-child{{border-bottom:none}}
.prog-label{{font-size:12px;width:230px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.prog-track{{flex:1;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;display:flex}}
.prog-p{{background:var(--pass);height:100%}}.prog-f{{background:var(--crit);height:100%}}.prog-w{{background:var(--med);height:100%}}
.prog-nums{{font-family:var(--mono);font-size:10px;color:var(--muted);width:100px;text-align:right;flex-shrink:0}}
.score-big{{font-family:var(--mono);font-size:44px;font-weight:700;color:{score_color};padding:18px 18px 4px}}
.score-sub{{font-size:12px;color:var(--muted);padding:0 18px 14px}}
.dur-row{{display:flex;justify-content:space-between;font-size:12px;padding:6px 0;border-bottom:1px solid var(--border)}}
.dur-row:last-child{{border-bottom:none}}
.dur-grid{{padding:14px 18px}}
.struct-entry{{font-family:var(--mono);font-size:11px;color:var(--muted);line-height:2;padding:14px 18px}}
.struct-entry span{{color:var(--accent)}}
</style>
</head>
<body>
<div id="nav-tooltip"></div>
<div class="shell">
<aside class="sidebar">
  <div class="logo">
    <div class="logo-title">K8S SECURITY</div>
    <div class="logo-sub">{h(meta_d.get("scan_id",""))}</div>
  </div>
  <div class="nav-sec">Report</div>
  <div class="nav-item active" onclick="show('overview',this)" ><span class="nav-dot" style="background:var(--accent)"></span>Overview</div>
  <div class="nav-sec">Scanners</div>
  <div class="nav-item" onclick="show('vulns',this)"><span class="nav-dot" style="background:var(--crit)"></span>SBOM <span class="nav-info" data-tip="Powered by Syft (SBOM) + Grype — vulnerabilities + license per image">&#9432;</span></div>
  <div class="nav-item" onclick="show('bench',this)"><span class="nav-dot" style="background:var(--high)"></span>CIS benchmark <span class="nav-info" data-tip="Powered by kube-bench — CIS Kubernetes Benchmark v1.6">&#9432;</span></div>
  <div class="nav-item" onclick="show('cluster',this)"><span class="nav-dot" style="background:var(--accent)"></span>Cluster checks <span class="nav-info" data-tip="Powered by kubectl — live cluster state, network policies and secrets inspection">&#9432;</span></div>
  <div class="nav-item" onclick="show('rbac',this)"><span class="nav-dot" style="background:var(--med)"></span>RBAC <span class="nav-info" data-tip="Powered by kubectl — live RBAC role and binding inspection">&#9432;</span></div>
  <div class="nav-item" onclick="show('iac',this)"><span class="nav-dot" style="background:#EF9F27"></span>YAML vulnerability <span class="nav-info" data-tip="Powered by Terrascan — IaC policy scanning for Kubernetes YAML manifests">&#9432;</span></div>
  <div class="nav-item" onclick="show('netexp',this)"><span class="nav-dot" style="background:var(--med)"></span>Network exposure <span class="nav-info" data-tip="Powered by kube-hunter — passive + active network reconnaissance">&#9432;</span></div>
  <div class="nav-sec">Export</div>
  <div class="nav-item" onclick="show('export',this)"><span class="nav-dot" style="background:var(--muted)"></span>JSON / Grafana <span class="nav-info" data-tip="master-report.json — enriched output from all scanners, Grafana-ready">&#9432;</span></div>
</aside>
<main class="main">

<div id="s-overview" class="section active">
  <div class="page-title">Overview</div>
  <div class="page-sub">ns:{h(meta_d.get("namespace",""))} &nbsp;|&nbsp; {h(meta_d.get("scan_id",""))} &nbsp;|&nbsp; {h(meta_d.get("timestamp",""))}</div>

  <div class="stat-grid" style="grid-template-columns:repeat(5,1fr)">
    <div class="stat c"><div class="stat-label">Critical CVEs</div><div class="stat-value">{vs2.get("critical",0)}</div><div class="stat-hint">Immediate action</div></div>
    <div class="stat h"><div class="stat-label">High CVEs</div><div class="stat-value">{vs2.get("high",0)}</div><div class="stat-hint">{vs2.get("total",0)} total · {vs2.get("images_scanned",0)} image(s)</div></div>
    <div class="stat c"><div class="stat-label">CIS Failures</div><div class="stat-value">{cis2.get("fail",0)}</div><div class="stat-hint">Score {cis2.get("score_pct",0)}% · {cis2.get("warn",0)} warns</div></div>
    <div class="stat {"c" if rbac_issues>0 else "p"}"><div class="stat-label">RBAC issues</div><div class="stat-value">{rbac_issues}</div><div class="stat-hint">{"secret access" if rbac_secret else "OK"}</div></div>
    <div class="stat {"c" if cl.get("no_network_policy") else "p"}"><div class="stat-label">Network policies</div><div class="stat-value">{cl.get("network_policies",0)}</div><div class="stat-hint">{"0 defined" if cl.get("no_network_policy") else "OK"}</div></div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">Top actions</div><div class="panel-badge">across all scanners</div></div>
      <div class="top-actions-wrap">{top_actions_html}</div>
    </div>
    <div style="display:flex;flex-direction:column;gap:16px">
      <div class="panel">
        <div class="panel-head"><div class="panel-title">Risk heatmap</div></div>
        <div class="heatmap-grid">
          <div class="hm-head"></div>
          <div class="hm-head">CIS</div><div class="hm-head">Vulns</div>
          <div class="hm-head">RBAC</div><div class="hm-head">Net</div><div class="hm-head">IaC</div>
          <div class="hm-row">Master</div>
          {hm_master_cis}
          {hm_master_vuln}
          {hm_master_rbac}
          {hm_master_net}
          {hm_master_iac}
          <div class="hm-row">Etcd</div>
          {hm_etcd_cis}
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-row">Worker</div>
          {hm_worker_cis}
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-row">Policies</div>
          {hm_pol_cis}
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
          <div class="hm-cell hm-n"><span class="hm-n">—</span></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><div class="panel-title">Exposed services</div></div>
        <div class="svc-list">{exposed_svc_rows}</div>
      </div>
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">CIS benchmark by node type</div></div>
      <div class="score-big">{cis2.get("score_pct",0)}%</div>
      <div class="score-sub">{cis2.get("pass",0)} pass | {cis2.get("fail",0)} fail | {cis2.get("warn",0)} warn | {h(cis2.get("cis_version",""))}</div>
      {bench_bars}
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">Scan metadata</div></div>
      <div class="meta-grid">
        <div class="meta-row"><div class="meta-key">Scan ID</div><div class="meta-val mono">{h(meta_d.get("scan_id",""))}</div></div>
        <div class="meta-row"><div class="meta-key">Timestamp</div><div class="meta-val">{h(meta_d.get("timestamp",""))}</div></div>
        <div class="meta-row"><div class="meta-key">Namespace</div><div class="meta-val mono">{h(meta_d.get("namespace",""))}</div></div>
        <div class="meta-row"><div class="meta-key">Total duration</div><div class="meta-val">{total_scan_secs}s</div></div>
      </div>
      <div class="panel-head" style="border-top:1px solid var(--border)"><div class="panel-title">Scanner durations</div></div>
      <div class="dur-grid">{dur_rows}</div>
    </div>
  </div>
</div>

<div id="s-vulns" class="section">
  <div class="page-title">SBOM</div>
  <div class="page-sub">Vulnerabilities + license composition per image · powered by Syft + Grype</div>
  <div class="stat-grid" style="grid-template-columns:repeat(6,1fr)">
    <div class="stat c"><div class="stat-label">Critical</div><div class="stat-value">{vs2.get("critical",0)}</div></div>
    <div class="stat h"><div class="stat-label">High</div><div class="stat-value">{vs2.get("high",0)}</div></div>
    <div class="stat m"><div class="stat-label">Medium</div><div class="stat-value">{vs2.get("medium",0)}</div></div>
    <div class="stat l"><div class="stat-label">Low</div><div class="stat-value">{vs2.get("low",0)}</div></div>
    <div class="stat {"c" if copyleft_count>0 else "p"}"><div class="stat-label">Copyleft licenses</div><div class="stat-value">{copyleft_count}</div></div>
    <div class="stat a"><div class="stat-label">Total packages</div><div class="stat-value">{total_license_pkgs}</div></div>
  </div>
  {"" if copyleft_count == 0 else '<div class="alert-box">Copyleft licenses (GPL/LGPL/AGPL) detected — legal review recommended before commercial distribution.</div>'}
  {sbom_img_panels}
</div>

<div id="s-bench" class="section">
  <div class="page-title">CIS Benchmark</div>
  <div class="page-sub">{h(cis2.get("cis_version",""))} | {cis2.get("total",0)} tests | score {cis2.get("score_pct",0)}%</div>
  <div class="stat-grid">
    <div class="stat p"><div class="stat-label">Pass</div><div class="stat-value">{cis2.get("pass",0)}</div></div>
    <div class="stat c"><div class="stat-label">Fail</div><div class="stat-value">{cis2.get("fail",0)}</div></div>
    <div class="stat m"><div class="stat-label">Warn</div><div class="stat-value">{cis2.get("warn",0)}</div></div>
    <div class="stat a"><div class="stat-label">Score</div><div class="stat-value">{cis2.get("score_pct",0)}%</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Failed Tests with Remediation</div><div class="panel-badge">{cis2.get("fail",0)}</div></div>
    <div class="tw"><table>
      <thead><tr><th>Test</th><th>Status</th><th>Section</th><th>Description</th><th>Remediation</th></tr></thead>
      <tbody>{cis_rows}</tbody>
    </table></div>
  </div>
</div>

<div id="s-cluster" class="section">
  <div class="page-title">Cluster checks</div>
  <div class="page-sub">Network policies · Kubernetes secrets · cluster topology</div>
  <div class="stat-grid" style="grid-template-columns:repeat(5,1fr)">
    <div class="stat a"><div class="stat-label">Nodes</div><div class="stat-value">{cl.get("nodes",0)}</div></div>
    <div class="stat h"><div class="stat-label">Exposed services</div><div class="stat-value">{cl.get("exposed_services",0)}</div></div>
    <div class="stat {"c" if no_netpol else "p"}"><div class="stat-label">Network policies</div><div class="stat-value">{total_netpols}</div><div class="stat-hint">{"" if no_netpol else "defined"}</div></div>
    <div class="stat {"h" if total_secrets>0 else "p"}"><div class="stat-label">Secrets</div><div class="stat-value">{total_secrets}</div><div class="stat-hint">{len(secrets_by_type)} type(s)</div></div>
    <div class="stat {"h" if cl.get("rbac_secret_access",0)>0 else "p"}"><div class="stat-label">Secret access roles</div><div class="stat-value">{cl.get("rbac_secret_access",0)}</div></div>
  </div>
  {net_warn_html}

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">Network policies</div>
      <div class="panel-badge">{total_netpols} defined</div>
    </div>
    {"" if netpol_rows else '<div style="padding:12px 16px;color:var(--crit);font-size:12px">No NetworkPolicy objects found — all pod-to-pod and ingress/egress traffic is unrestricted. Define policies to limit blast radius.</div>'}
    {"" if not netpol_rows else '<div class="tw"><table><thead><tr><th>Name</th><th>Namespace</th><th>Types</th><th style="text-align:right">Ingress rules</th><th style="text-align:right">Egress rules</th></tr></thead><tbody>' + netpol_rows + '</tbody></table></div>'}
  </div>

  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">Kubernetes secrets</div>
      <div class="panel-badge">{total_secrets} total</div>
    </div>
    {"" if total_secrets == 0 else '<div class="panel-head" style="border-bottom:1px solid var(--border)"><div style="font-size:11px;color:var(--muted)">By type</div></div><div class="tw"><table><thead><tr><th>Type</th><th style="text-align:right">Count</th></tr></thead><tbody>' + secrets_type_rows + '</tbody></table></div>'}
    {"" if not secret_rows else '<div class="tw" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Namespace</th><th>Type</th><th style="text-align:right">Keys</th><th>Classification</th><th>Created</th></tr></thead><tbody>' + secret_rows + '</tbody></table></div>'}
    {"" if total_secrets > 0 else '<div style="padding:12px 16px;color:var(--muted);font-size:12px">No secrets found in this namespace.</div>'}
  </div>
</div>

<div id="s-rbac" class="section">
  <div class="page-title">RBAC</div>
  <div class="page-sub">Roles and RoleBindings with secret access and sensitive verb flags</div>
  <div class="stat-grid">
    <div class="stat a"><div class="stat-label">Roles</div><div class="stat-value">{cl.get("rbac_roles",0)}</div></div>
    <div class="stat a"><div class="stat-label">RoleBindings</div><div class="stat-value">{cl.get("rbac_bindings",0)}</div></div>
    <div class="stat {"h" if cl.get("rbac_secret_access",0)>0 else "p"}"><div class="stat-label">Secret Access</div><div class="stat-value">{cl.get("rbac_secret_access",0)}</div></div>
    <div class="stat p"><div class="stat-label">ClusterRoles</div><div class="stat-value">0</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Roles and Bindings</div></div>
    <div class="tw"><table>
      <thead><tr><th>Name</th><th>Kind</th><th>Rules / Binding</th><th>Flags</th></tr></thead>
      <tbody>{rbac_rows}</tbody>
    </table></div>
  </div>
</div>

<div id="s-iac" class="section">
  <div class="page-title">YAML vulnerability</div>
  <div class="page-sub">{h(str(iac.get("policies_validated",0)))} policies validated | {h(str(iac.get("violated_policies",0)))} violations</div>
  <div class="stat-grid">
    <div class="stat {"c" if iac.get("high",0)>0 else "p"}"><div class="stat-label">High</div><div class="stat-value">{iac.get("high",0)}</div></div>
    <div class="stat {"m" if iac.get("medium",0)>0 else "p"}"><div class="stat-label">Medium</div><div class="stat-value">{iac.get("medium",0)}</div></div>
    <div class="stat {"l" if iac.get("low",0)>0 else "p"}"><div class="stat-label">Low</div><div class="stat-value">{iac.get("low",0)}</div></div>
    <div class="stat a"><div class="stat-label">Policies Validated</div><div class="stat-value">{iac.get("policies_validated",0)}</div></div>
  </div>
  {ts_viol_panel}
  {ts_err_panel}
</div>



<div id="s-netexp" class="section">
  <div class="page-title">Network exposure</div>
  <div class="page-sub">kube-hunter passive + active network reconnaissance — discovered nodes and exposed services</div>
  <div class="stat-grid">
    <div class="stat a"><div class="stat-label">Nodes discovered</div><div class="stat-value">{len((sc.get("kube_hunter_passive") or {{}}).get("nodes",[]))}</div></div>
    <div class="stat {"c" if len((sc.get("kube_hunter_passive") or {{}}).get("services",[]))>0 else "p"}"><div class="stat-label">Exposed services</div><div class="stat-value">{len((sc.get("kube_hunter_passive") or {{}}).get("services",[]))}</div></div>
    <div class="stat {"c" if len((sc.get("kube_hunter_passive") or {{}}).get("vulnerabilities",[]))>0 else "p"}"><div class="stat-label">Vulnerabilities</div><div class="stat-value">{len((sc.get("kube_hunter_passive") or {{}}).get("vulnerabilities",[]))}</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Discovered nodes</div></div>
    <div class="tw"><table>
      <thead><tr><th>Node</th><th>Type</th></tr></thead>
      <tbody>{"".join(f'<tr><td class="mono">{h(n.get("location",""))}</td><td>{h(n.get("type",""))}</td></tr>' for n in (sc.get("kube_hunter_passive") or {{}}).get("nodes",[]))}</tbody>
    </table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Exposed services</div></div>
    <div class="tw"><table>
      <thead><tr><th>Service</th><th>Location</th><th>Risk</th></tr></thead>
      <tbody>{svc_risk_rows}</tbody>
    </table></div>
  </div>
</div>

<div id="s-export" class="section">
  <div class="page-title">JSON Export and Grafana Integration</div>
  <div class="page-sub">Download the enriched master-report.json for Grafana, dashboards, or any external tool</div>
  <a class="dl-btn" id="dl-btn" href="#" download="master-report.json">Download master-report.json</a>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">JSON Schema</div></div>
    <div class="struct-entry">
      <div><span>meta</span> -> scan_id, timestamp, namespace, scanner_durations</div>
      <div><span>summary.vulnerabilities</span> -> critical, high, medium, low, total, images_scanned</div>
      <div><span>summary.cis_benchmark</span> -> pass, fail, warn, total, score_pct, cis_version</div>
      <div><span>summary.cluster</span> -> nodes, exposed_services, network_policies, secrets_total, rbac_roles</div>
      <div><span>summary.iac</span> -> policies_validated, violated_policies, high, medium, low</div>
      <div><span>scanners.syft_grype.images[].vulnerabilities[]</span> -> id, severity, cvss_score, package, fix_available, fix_versions, urls</div>
      <div><span>scanners.kube_bench.sections[].findings[]</span> -> test_number, status, remediation, audit, expected, actual</div>
      <div><span>scanners.kube_hunter_passive/active</span> -> nodes[], services[], vulnerabilities[]</div>
      <div><span>scanners.rbac</span> -> roles[].{{rules, sensitive_verbs, secret_access}}, role_bindings[]</div>
      <div><span>scanners.network_policies</span> -> policies[].{{ingress_rules, egress_rules, policy_types}}</div>
      <div><span>scanners.terrascan</span> -> violations[].{{rule_name, severity, remediation, reference_link}}</div>
    </div>
  </div>
</div>

</main>
</div>
<script>
function showTip(e,el){{
  var t=document.getElementById('nav-tooltip');
  t.textContent=el.getAttribute('data-tip');
  t.style.display='block';
  t.style.left='-9999px'; t.style.top='-9999px';
  var tw=t.offsetWidth, th=t.offsetHeight;
  var x=e.clientX+14, y=e.clientY-8;
  if(x+tw>window.innerWidth-10) x=e.clientX-tw-10;
  if(y+th>window.innerHeight-10) y=e.clientY-th-8;
  if(x<8) x=8; if(y<8) y=8;
  t.style.left=x+'px'; t.style.top=y+'px';
}}
function hideTip(){{document.getElementById('nav-tooltip').style.display='none';}}
function show(id, el) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('s-' + id).classList.add('active');
  el.classList.add('active');
}}
document.querySelectorAll('.nav-info').forEach(el => {{
  el.addEventListener('mousemove', e => {{
    var t=document.getElementById('nav-tooltip');
    if(t.style.display==='block'){{
      var tw=t.offsetWidth,th=t.offsetHeight;
      var x=e.clientX+14,y=e.clientY-8;
      if(x+tw>window.innerWidth-10) x=e.clientX-tw-10;
      if(y+th>window.innerHeight-10) y=e.clientY-th-8;
      if(x<8)x=8; if(y<8)y=8;
      t.style.left=x+'px'; t.style.top=y+'px';
    }}
  }});
}});
const blob = new Blob([JSON.stringify({json_blob}, null, 2)], {{type:'application/json'}});
document.getElementById('dl-btn').href = URL.createObjectURL(blob);
</script>
</body>
</html>"""

with open(html_path, "w") as f:
    f.write(html_out)
print(f"[+] HTML report  -> {html_path}")
PYEOF
}

# ==============================
# Main
# ==============================
main() {
    check_dependencies
    interactive_setup

    run_kube_hunter
    run_kube_bench
    run_terrascan
    run_syft_grype
    run_k8s_checks

    build_master_report

    local END
    END=$(date +%s)
    local TOTAL=$(( END - SCRIPT_START_TIME ))

    echo ""
    log_good "=============================================="
    log_good "Scan complete in $(format_duration $TOTAL)"
    log_good "Output: $RUN_DIR"
    log_good ""
    log_good "  master-report.json  - enriched JSON (Grafana/dashboard-ready)"
    log_good "  ${SCAN_ID}.html      - self-contained HTML with JSON download"
    log_good "  scan-results/       - individual raw scanner outputs"
    log_good "  sbom/               - per-image SBOM + vulnerability files"
    log_good "  logs/               - scanner stderr logs"
    log_good "=============================================="
}

main "$@"
