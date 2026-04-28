#!/bin/bash
set -e

# Get the directory where this script is installed
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
OUTPUT_DIR="${SCRIPT_DIR}/output"
DATA_DIR="${SCRIPT_DIR}/data"
CACHE_DIR="${SCRIPT_DIR}/malicious-packages"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
print_error() {
    echo -e "${RED}[!] $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}" >&2
}

print_info() {
    echo -e "${BLUE}[*] $1${NC}" >&2
}

# Function to check and download dataset if needed
ensure_dataset() {
    if [ ! -d "$CACHE_DIR" ]; then
        print_info "Fetching OpenSSF malicious packages dataset..."
        git clone -q https://github.com/ossf/malicious-packages "$CACHE_DIR"
    else
        print_info "Updating existing malicious dataset..."
        cd "$CACHE_DIR" && git pull -q origin main 2>/dev/null && cd "$SCRIPT_DIR"
    fi
    print_success "Dataset ready"
}

# Function to build index if it doesn't exist
ensure_index() {
    if [ ! -f "$DATA_DIR/malicious_index.json" ]; then
        print_info "Building malicious package index..."
        python3 "$SCRIPT_DIR/malicious_db_loader.py"
        print_success "Index built"
    fi
}

# Function to check single package
check_single_package() {
    local input="$1"
    local ecosystem="pypi"
    local name="$input"
    
    # Detect if it's a PURL (pkg:ecosystem/name@version)
    if [[ "$input" == pkg:* ]]; then
        ecosystem=$(echo "$input" | sed 's/pkg:\([^/]*\).*/\1/')
        name=$(echo "$input" | sed 's/.*\/\([^@]*\).*/\1/')
    fi
    
    print_info "Checking package: $name ($ecosystem)"
    ensure_dataset
    ensure_index
    
    python3 "$SCRIPT_DIR/risk_engine.py" "$name" "$ecosystem" --terminal
    return $?
}

# Function to scan SBOM file
scan_sbom_file() {
    local sbom_file="$1"
    
    # Check if file exists FIRST
    if [ ! -f "$sbom_file" ]; then
        print_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    # Convert to absolute path if relative
    if [[ ! "$sbom_file" = /* ]]; then
        sbom_file="$(pwd)/$sbom_file"
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Get SBOM filename without extension
    local sbom_basename=$(basename "$sbom_file")
    local sbom_name="${sbom_basename%.*}"
    local output_json="${OUTPUT_DIR}/${sbom_name}-results.json"

    # Download/Update dataset
    ensure_dataset

    # Build index
    print_info "Building malicious package index..."
    python3 "$SCRIPT_DIR/malicious_db_loader.py"
    print_success "Index built"

    # Scan SBOM
    print_info "Scanning SBOM: $sbom_file"

    local temp_output="${OUTPUT_DIR}/.tmp_results.json"

    echo "[" > "$temp_output"
    local first_entry=true
    local processed=0
    local total=$(jq -r '.components[] | select(.purl != null) | .purl' "$sbom_file" 2>/dev/null | wc -l)

    jq -r '.components[] | select(.purl != null) | .purl' "$sbom_file" 2>/dev/null | while read -r purl; do
        processed=$((processed + 1))
        
        local ecosystem=$(echo "$purl" | cut -d':' -f2 | cut -d'/' -f1)
        local name=$(echo "$purl" | cut -d'/' -f2 | cut -d'@' -f1)
        local version=$(echo "$purl" | cut -d'@' -f2)
        
        print_info "Analyzing package [$processed/$total]: $name@$version ($ecosystem)"
        
        result=$(python3 "$SCRIPT_DIR/risk_engine.py" "$name" "$ecosystem" 2>/dev/null)
        
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

# Main logic
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <package-name|purl|sbom.json>"
    echo ""
    echo "Examples:"
    echo "  $0 requests                              # Check PyPI package"
    echo "  $0 pkg:pypi/requests@2.31.0             # Check with PURL"
    echo "  $0 pkg:npm/lodash@4.17.21               # Check NPM package"
    echo "  $0 sbom.json                             # Scan SBOM file"
    exit 1
fi

input="$1"

# Check input type FIRST - before any operations
if [[ "$input" == pkg:* ]]; then
    check_single_package "$input"
    exit $?
elif [[ "$input" == *.json ]]; then
    scan_sbom_file "$input"
    exit $?
else
    check_single_package "$input"
    exit $?
fi