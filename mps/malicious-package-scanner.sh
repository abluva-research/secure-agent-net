#!/bin/bash
set -e

SBOM_FILE="$1"
OUTPUT_JSON="output/results.json"

if [ -z "$SBOM_FILE" ]; then
  echo "Usage: $0 <sbom.json>"
  exit 1
fi

mkdir -p output

echo "[+] Checking OpenSSF malicious dataset..."

if [ -d "malicious-packages" ]; then
  echo "[+] Updating existing malicious dataset..."
  cd malicious-packages && git pull && cd ..
else
  echo "[+] Cloning malicious dataset..."
  git clone https://github.com/ossf/malicious-packages
fi

echo "[+] Building malicious package index..."
python3 malicious_db_loader.py

echo "[" > "$OUTPUT_JSON"
first_entry=true

jq -r '.components[] | select(.purl != null) | .purl' "$SBOM_FILE" | while read -r purl; do
  ecosystem=$(echo "$purl" | cut -d':' -f2 | cut -d'/' -f1)
  name=$(echo "$purl" | cut -d'/' -f2 | cut -d'@' -f1)

  echo "[*] Analyzing: $name ($ecosystem)"
  result=$(python3 risk_engine.py "$name" "$ecosystem")

  if [ "$first_entry" = true ]; then
    first_entry=false
  else
    echo "," >> "$OUTPUT_JSON"
  fi

  echo "$result" >> "$OUTPUT_JSON"
done

echo "]" >> "$OUTPUT_JSON"
echo "[+] Scan completed → $OUTPUT_JSON"
