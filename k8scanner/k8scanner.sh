#!/usr/bin/env bash
# k8scanner.sh -- version v1.0
# Modular Kubernetes security scanner
# Features: kube-hunter, kube-bench, terrascan, syft/grype (SBOM + vulnerabilities)
# Outputs JSON + logs and aggregates master report
# Cleanup trap included

set -euo pipefail

# ==============================
# Globals
# ==============================
RUN_TIMESTAMP=$(date +"%d-%m-%Y_%H-%M-%S")
OUTPUT_ROOT=""
RUN_DIR=""
TMP_KUBECONFIG=""
IAC_DIR=""
NAMESPACES=()
THREADS=4

# ==============================
# Logging helpers
# ==============================
log_info()  { echo -e "[i] $*"; }
log_good()  { echo -e "[+] $*"; }
log_warn()  { echo -e "[WARN] $*"; }
log_error() { echo -e "[ERR] $*"; }

# ==============================
# Cleanup on exit (trap)
# ==============================
cleanup() {
    log_info "Cleaning up temporary resources..."
    if [[ -n "$TMP_KUBECONFIG" && -f "$TMP_KUBECONFIG" ]]; then
        rm -f "$TMP_KUBECONFIG"
        log_info "Removed temporary kubeconfig: $TMP_KUBECONFIG"
    fi
    docker ps -q --filter "label=k8s-scan-temp" | xargs -r docker rm -f >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# ==============================
# Interactive setup
# ==============================
interactive_setup() {
    # Output directory
    read -p "Output root directory (default: ./scans): " OUTPUT_ROOT
    OUTPUT_ROOT=${OUTPUT_ROOT:-./scans}
    RUN_DIR="$OUTPUT_ROOT/$RUN_TIMESTAMP"
    mkdir -p "$RUN_DIR"
    log_info "Run dir: $RUN_DIR"

    # Master report option
    read -p "Create aggregated master report at end? (y/N): " CREATE_REPORT
    CREATE_REPORT=${CREATE_REPORT:-N}

    # IaC/YAML folder
    read -p "Enter path to folder containing IaC/YAML files (default: current directory): " IAC_DIR
    IAC_DIR=${IAC_DIR:-$PWD}
    if [[ ! -d "$IAC_DIR" ]]; then
        log_warn "Directory $IAC_DIR does not exist. Using current directory."
        IAC_DIR="$PWD"
    fi
    log_info "IaC/YAML folder set to: $IAC_DIR"

    # Kubernetes authentication
    echo
    log_info "Kubernetes authentication — choose method:"
    echo "  1) Use existing KUBECONFIG context (default)"
    echo "  2) Provide API server URL + Bearer token (temporary kubeconfig)"
    read -p "Select 1 or 2 [1]: " AUTH_METHOD
    AUTH_METHOD=${AUTH_METHOD:-1}

    if [[ "$AUTH_METHOD" == "2" ]]; then
        read -p "API Server URL (e.g. https://1.2.3.4:6443): " API_SERVER
        read -p "Bearer token (paste): " BEARER_TOKEN

        TMP_KUBECONFIG=$(mktemp /tmp/tmp.kubeconfig.XXXX)
        cat > "$TMP_KUBECONFIG" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: $API_SERVER
    insecure-skip-tls-verify: true
  name: temp-cluster
contexts:
- context:
    cluster: temp-cluster
    namespace: default
    user: temp-user
  name: temp-context
current-context: temp-context
users:
- name: temp-user
  user:
    token: $BEARER_TOKEN
EOF
        export KUBECONFIG="$TMP_KUBECONFIG"
        log_info "Temporary kubeconfig created at $TMP_KUBECONFIG"
    fi

    # Validate access
    if ! kubectl get ns >/dev/null 2>&1; then
        log_error "kubectl cannot access cluster with given context/credentials."
        exit 1
    fi
    # Namespace selection
    read -p "Enter comma-separated namespaces for Syft/Grype scan (default: default): " NS_INPUT
    NS_INPUT=${NS_INPUT:-default}
    IFS=',' read -ra NAMESPACES <<< "$NS_INPUT"
    log_info "Namespaces to scan: ${NAMESPACES[*]}"
}

# ==============================
# Scanners
# ==============================

run_kube_hunter() {
    # Ensure KUBECONFIG is defined
    KUBE_CONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
    if [[ ! -f "$KUBE_CONFIG_PATH" ]]; then
        log_error "Kubeconfig file not found at $KUBE_CONFIG_PATH"
        return 1
    fi

    # ---------------------------
    # Passive Scan
    # ---------------------------
    PASSIVE_JSON="$RUN_DIR/kube-hunter-passive.json"
    PASSIVE_LOG="$RUN_DIR/kube-hunter-passive.log"

    log_good "Running kube-hunter passive scan (cluster-wide, JSON + logs)..."
    docker run --rm -t --net host \
        -v "$KUBE_CONFIG_PATH:/root/.kube/config:ro" \
        aquasec/kube-hunter \
        --kubeconfig /root/.kube/config \
        --k8s-auto-discover-nodes \
        --report json \
        > "$PASSIVE_JSON" 2> "$PASSIVE_LOG"

    log_info "Passive scan complete."
    log_info "Raw JSON results: $PASSIVE_JSON"
    log_info "Logs: $PASSIVE_LOG"

    # ---------------------------
    # Active Scan
    # ---------------------------
    ACTIVE_JSON="$RUN_DIR/kube-hunter-active.json"
    ACTIVE_LOG="$RUN_DIR/kube-hunter-active.log"

    log_good "Running kube-hunter active scan (probing vulnerabilities, JSON + logs)..."
    docker run --rm -t --net host \
        -v "$KUBE_CONFIG_PATH:/root/.kube/config:ro" \
        aquasec/kube-hunter \
        --kubeconfig /root/.kube/config \
        --list \
        --active \
        --report json \
        > "$ACTIVE_JSON" 2> "$ACTIVE_LOG" 

    log_info "Active scan complete."
    log_info "Raw JSON results: $ACTIVE_JSON"
    log_info "Logs: $ACTIVE_LOG"
}

run_kube_bench() {
    log_good "Running kube-bench..."
    docker run --rm -t \
      --label k8s-scan-temp \
      --net host \
      --pid host \
      -v /etc:/etc:ro \
      -v /var:/var:ro \
      aquasec/kube-bench \
      --json \
      > "$RUN_DIR/kube-bench.json"
}

run_terrascan() {
    log_good "Running terrascan..."
    docker run --rm -t \
      --label k8s-scan-temp \
      -v "$IAC_DIR":/iac \
      tenable/terrascan \
      scan -d /iac -o json \
      > "$RUN_DIR/terrascan.json" || log_warn "Terrascan may have found no IaC configs"
    log_info "Terrascan scan complete. Output saved at $RUN_DIR/terrascan.json"
}

run_syft_grype() {
    for ns in "${NAMESPACES[@]}"; do
        log_info "Scanning namespace: $ns"

        # Collect all images from pods, deployments, daemonsets, statefulsets
        images=$(kubectl get pods,deployments,daemonsets,statefulsets -n "$ns" -o jsonpath="{..image}" 2>/dev/null | tr -s '[[:space:]]' '\n' | sort -u)
        [[ -z "$images" ]] && { log_warn "No images found in namespace $ns"; continue; }

        SBOM_DIR="$RUN_DIR/sbom/$ns"
        mkdir -p "$SBOM_DIR"

        SYFT_JSON_LIST=()
        GRYPE_JSON_LIST=()

        for img in $images; do
            safe_name=$(echo "$img" | tr '/:' '__')
            sbom_file="$SBOM_DIR/$safe_name.json"
            grype_file="$SBOM_DIR/grype-$safe_name.json"

            log_good "Generating SBOM for image: $img"
            docker run --rm -v "$SBOM_DIR":/scans anchore/syft:latest "$img" -o cyclonedx-json="/scans/$safe_name.json"

            log_good "Scanning SBOM for vulnerabilities with Grype..."
            docker run --rm -v "$SBOM_DIR":/scans anchore/grype:latest sbom:/scans/"$safe_name.json" -o json > "$grype_file"

            SYFT_JSON_LIST+=("$sbom_file")
            GRYPE_JSON_LIST+=("$grype_file")
        done

        # Merge per-namespace SBOMs for master report
        jq -s 'reduce .[] as $item ({}; . * $item)' "${SYFT_JSON_LIST[@]}" > "$RUN_DIR/syft-sbom-$ns.json"
        jq -s 'reduce .[] as $item ({}; . * $item)' "${GRYPE_JSON_LIST[@]}" > "$RUN_DIR/grype-$ns.json"
    done
}

# ==============================
# Master report aggregation
# ==============================
aggregate_reports() {
    if [[ "$CREATE_REPORT" =~ ^[Yy]$ ]]; then
        log_good "Aggregating all reports into master JSON..."
        MASTER_FILE="$RUN_DIR/master-report.json"

        # Initialize jq object
        jq -n '{}' > "$MASTER_FILE"

        # Add cluster-wide scanners
        for report in kube-hunter-passive.json kube-hunter-active.json kube-bench.json terrascan.json; do
            report_path="$RUN_DIR/$report"
            [[ -s "$report_path" ]] || echo '{}' > "$report_path"
            key=$(basename "$report" .json)
            jq --arg key "$key" --argfile data "$report_path" '.[$key] = $data' "$MASTER_FILE" > "$MASTER_FILE.tmp" && mv "$MASTER_FILE.tmp" "$MASTER_FILE"
        done

        # Add namespace-specific Syft/Grype reports
        for ns in "${NAMESPACES[@]}"; do
            SYFT_NS_FILE="$RUN_DIR/syft-sbom-$ns.json"
            GRYPE_NS_FILE="$RUN_DIR/grype-$ns.json"

            [[ -s "$SYFT_NS_FILE" ]] || echo '{}' > "$SYFT_NS_FILE"
            [[ -s "$GRYPE_NS_FILE" ]] || echo '{}' > "$GRYPE_NS_FILE"

            jq --arg ns "$ns" --argfile syft "$SYFT_NS_FILE" --argfile grype "$GRYPE_NS_FILE" \
              '.[$ns] = { syft: $syft, grype: $grype } + .' \
              "$MASTER_FILE" > "$MASTER_FILE.tmp" && mv "$MASTER_FILE.tmp" "$MASTER_FILE"
        done

        log_good "✅ Master report successfully created at: $MASTER_FILE"
        log_info "Includes: Cluster-wide + per-namespace results"
    fi
}

# ==============================
# Main
# ==============================
main() {
    interactive_setup
    run_kube_hunter
    run_kube_bench
    run_terrascan
    run_syft_grype
    aggregate_reports
    log_good "Scan complete. Results saved in $RUN_DIR"
}

main "$@"
