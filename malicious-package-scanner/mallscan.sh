#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/data"
CACHE_DIR="${SCRIPT_DIR}/malicious-packages"
OSV_CACHE_DIR="${SCRIPT_DIR}/osv-data"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m'

print_error() { echo -e "${RED}[!] $1${NC}" >&2; }
print_success() { echo -e "${GREEN}[+] $1${NC}" >&2; }
print_info() { echo -e "${BLUE}[*] $1${NC}" >&2; }
print_warn() { echo -e "${YELLOW}[⚠] $1${NC}" >&2; }

# ==============================================================================
# OPENSSF DATASET MANAGEMENT
# ==============================================================================

ensure_openssf_dataset() {
    if [ ! -d "$CACHE_DIR" ]; then
        print_info "Fetching OpenSSF malicious packages dataset..."
        cd "$SCRIPT_DIR"
        git clone https://github.com/ossf/malicious-packages 2>/dev/null || true
    else
        print_info "Updating existing OpenSSF dataset..."
        cd "$CACHE_DIR" 2>/dev/null
        timeout 10 git pull origin main 2>/dev/null || true
        cd "$SCRIPT_DIR" 2>/dev/null
    fi
    print_success "OpenSSF dataset ready"
}

is_openssf_index_valid() {
    if [ ! -f "$DATA_DIR/malicious_index.json" ]; then
        return 1
    fi
    local size=$(stat -f%z "$DATA_DIR/malicious_index.json" 2>/dev/null || stat -c%s "$DATA_DIR/malicious_index.json" 2>/dev/null || echo "0")
    if [ "$size" -lt 100 ]; then
        return 1
    fi
    return 0
}

ensure_openssf_index() {
    if ! is_openssf_index_valid; then
        print_info "Building OpenSSF package index..."
        python3 "$SCRIPT_DIR/malicious_db_loader.py"
        print_success "OpenSSF index built"
    fi
}

# ==============================================================================
# OSV DATASET MANAGEMENT
# ==============================================================================

ensure_osv_dataset() {
    if [ ! -d "$OSV_CACHE_DIR" ]; then
        print_info "Setting up OSV dataset cache..."
        mkdir -p "$OSV_CACHE_DIR"
    fi
    print_success "OSV dataset ready"
}

# ==============================================================================
# PACKAGE CHECKING LOGIC
# ==============================================================================

check_single_package() {
    local input="$1"
    local ecosystem="pypi"
    local name="$input"
    local version=""
    
    # Parse PURL format: pkg:ecosystem/name@version
    if [[ "$input" == pkg:* ]]; then
        ecosystem=$(echo "$input" | sed 's/pkg:\([^/]*\).*/\1/')
        local full_purl=$(echo "$input" | sed 's/pkg:[^/]*\///')
        name=$(echo "$full_purl" | sed 's/@.*$//')
        version=$(echo "$full_purl" | sed 's/^[^@]*@//' || echo "")
    fi
    
    print_info "Checking package: $name ($ecosystem)"
    [ -n "$version" ] && print_info "Version: $version"
    
    ensure_openssf_dataset
    ensure_openssf_index
    ensure_osv_dataset
    
    # Run combined check with both OpenSSF and OSV
    python3 "$SCRIPT_DIR/risk_engine.py" \
        --name "$name" \
        --ecosystem "$ecosystem" \
        ${version:+--version "$version"} \
        --terminal \
        --combine-sources
    return $?
}

# ==============================================================================
# SBOM SCANNING
# ==============================================================================

scan_sbom_file() {
    local sbom_file="$1"
    
    if [ ! -f "$sbom_file" ]; then
        print_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    local sbom_dir=$(cd "$(dirname "$sbom_file")" && pwd)
    local sbom_basename=$(basename "$sbom_file")
    local sbom_name="${sbom_basename%.*}"
    local output_json="${sbom_dir}/${sbom_name}-results.json"

    print_info "Preparing datasets..."
    ensure_openssf_dataset
    ensure_osv_dataset
    
    print_info "Building OpenSSF package index..."
    python3 "$SCRIPT_DIR/malicious_db_loader.py"
    print_success "Index built"

    print_info "Scanning SBOM: $sbom_file"

    local temp_output="${sbom_dir}/.tmp_results.json"
    echo "[" > "$temp_output"
    local first_entry=true
    local processed=0
    local total=$(jq -r '.components[] | select(.purl != null) | .purl' "$sbom_file" 2>/dev/null | wc -l)

    jq -r '.components[] | select(.purl != null) | .purl' "$sbom_file" 2>/dev/null | while read -r purl; do
        processed=$((processed + 1))
        
        local ecosystem=$(echo "$purl" | cut -d':' -f2 | cut -d'/' -f1)
        local full_purl=$(echo "$purl" | sed 's/pkg:[^/]*\///')
        local name=$(echo "$full_purl" | sed 's/@.*$//')
        local version=$(echo "$purl" | cut -d'@' -f2)
        
        print_info "Analyzing package [$processed/$total]: $name@$version ($ecosystem)"
        
        result=$(python3 "$SCRIPT_DIR/risk_engine.py" \
            --name "$name" \
            --ecosystem "$ecosystem" \
            --version "$version" \
            --combine-sources \
            2>/dev/null)
        
        if [ "$first_entry" = true ]; then
            first_entry=false
        else
            echo "," >> "$temp_output"
        fi
        
        echo "$result" >> "$temp_output"
    done

    echo "]" >> "$temp_output"
    mv "$temp_output" "$output_json"

    print_success "Scan completed"
    print_info "Results saved to: $output_json"
    print_info ""
    jq '.' "$output_json" 2>/dev/null | head -50
}

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

show_usage() {
    print_error "Usage: mallscan [OPTIONS] <package-name|purl|sbom.json>"
    echo ""
    echo "Options:"
    echo "  --osv-only              Check only against OSV dataset"
    echo "  --openssf-only          Check only against OpenSSF dataset"
    echo "  --combine               Combine both datasets (default for SBOM)"
    echo ""
    echo "Examples:"
    echo "  mallscan requests"
    echo "  mallscan pkg:npm/@scope/package@1.0.0"
    echo "  mallscan pkg:pypi/django@3.2.0"
    echo "  mallscan sbom.json"
    echo "  mallscan --osv-only requests"
}

if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

# Parse options
osv_only=false
openssf_only=false
combine_sources=false
input=""

while [ $# -gt 0 ]; do
    case "$1" in
        --osv-only)
            osv_only=true
            shift
            ;;
        --openssf-only)
            openssf_only=true
            shift
            ;;
        --combine)
            combine_sources=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            input="$1"
            shift
            ;;
    esac
done

if [ -z "$input" ]; then
    show_usage
    exit 1
fi

# Route to appropriate handler
if [[ "$input" == *.json ]]; then
    scan_sbom_file "$input"
    exit $?
elif [[ "$input" == pkg:* ]] || [[ "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    check_single_package "$input"
    exit $?
else
    print_error "Invalid input format"
    show_usage
    exit 1
fi
