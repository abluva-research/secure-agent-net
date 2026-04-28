# 🔍 Malicious Package Scanner

A lightweight CLI tool to detect malicious packages in your software dependencies using the OpenSSF malicious packages database.

## ✨ Features

- **Fast scanning** - Check packages in seconds
- **Multiple input formats** - Single package, PURL, or SBOM file
- **Risk scoring** - 0-100 risk score for each package
- **4 detection methods** - Malicious list, typosquatting, age, popularity
- **Global command** - Works from anywhere: `mallscan`
- **Smart output** - Terminal display for single packages, JSON for SBOM scans
- **Auto dataset updates** - Always uses latest OpenSSF data

## 🚀 Quick Start

### Installation

```bash
# Extract and install
unzip malicious-package-scanner.zip
cd malicious-package-scanner
chmod +x install.sh
sudo ./install.sh
```

### Usage

```bash
# Check single package by name
mallscan requests

# Check with PURL format
mallscan pkg:pypi/requests@2.31.0
mallscan pkg:npm/lodash@4.17.21

# Scan entire SBOM file
mallscan sbom.json
# Output: output/sbom-results.json
```

## 📋 How It Works

The tool analyzes packages and calculates risk scores based on 4 factors:

| Detection Method | Risk Points | What It Detects |
|---|---|---|
| **MALICIOUS_KNOWN** | +100 | Package in OpenSSF malicious list |
| **TYPOSQUAT** | +40 | Suspicious name similarity (e.g., `reqeusts` vs `requests`) |
| **NEW_PACKAGE** | +20 | Published less than 7 days ago |
| **LOW_POPULARITY** | +10 | Very few versions in registry |

### Risk Score Levels

- **0-20**: ✅ **SAFE** - No issues detected
- **21-50**: ⚠️ **CAUTION** - Review before use
- **51-80**: ⚠️⚠️ **HIGH RISK** - Avoid if possible
- **81-100**: 🚨 **CRITICAL** - Do not use

## 📊 Examples

### Single Package Check

```bash
$ mallscan requests

==================================================
Package Analysis Result
==================================================

Package:     requests
Ecosystem:   pypi
Status:      ✅ SAFE
Risk Score:  0/100
Details:     No risks found

==================================================
```

### PURL Format Check

```bash
$ mallscan pkg:npm/lodash@4.17.21

==================================================
Package Analysis Result
==================================================

Package:     lodash
Ecosystem:   npm
Status:      ✅ SAFE
Risk Score:  0/100
Details:     No risks found

==================================================
```

### SBOM File Scan

```bash
$ mallscan Interface-Dac-sbom.json

[*] Fetching OpenSSF malicious packages dataset...
[+] Dataset ready
[*] Building malicious package index...
[+] Index built successfully: 8234 malicious packages indexed
[*] Scanning SBOM: Interface-Dac-sbom.json
[*] Analyzing package [1/458]: GRKOpenSSLFramework@1.0.2.16 (cocoapods)
[*] Analyzing package [2/458]: requests@2.31.0 (pypi)
[+] Scan completed
[*] Results saved to: output/Interface-Dac-results.json
```

## 📁 Output File

When scanning SBOM files, results are saved with the SBOM name:

```bash
mallscan my-project-sbom.json
# Output: output/my-project-results.json

cat output/my-project-results.json
```

JSON output format:

```json
[
  {
    "package": "requests",
    "ecosystem": "pypi",
    "risks": [],
    "risk_score": 0
  },
  {
    "package": "malicious-lib",
    "ecosystem": "pypi",
    "risks": [
      {
        "type": "MALICIOUS_KNOWN"
      }
    ],
    "risk_score": 100
  }
]
```

## 🎯 Supported Ecosystems

- **PyPI** - Python packages
- **NPM** - Node.js packages
- **More** - Any ecosystem supported by PURL format

## 🔧 System Requirements

- Python 3.7+
- `jq` (JSON processor)
- `git` (for dataset management)
- `pip` (for Python dependencies)

### Install Requirements

**Ubuntu/Debian:**
```bash
sudo apt-get install jq git python3 python3-pip
```

**macOS:**
```bash
brew install jq git python3
```

## 📚 SBOM Format

Expected input format (Package URL / PURL):

```json
{
  "components": [
    {"purl": "pkg:pypi/requests@2.31.0"},
    {"purl": "pkg:npm/lodash@4.17.21"},
    {"purl": "pkg:pypi/malware@1.0.0"}
  ]
}
```

Generate SBOM using:
- **Syft**: `syft <project> -o json > sbom.json`
- **CycloneDX CLI**: `cyclonedx-bom`
- **FOSSA**: `fossa analyze`

## ⚙️ Installation Options

### System-wide (recommended)

```bash
sudo ./install.sh
# Command: mallscan
```

### User-local

```bash
./install.sh ~/.local/lib/malicious-package-scanner ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"
```

### Custom path

```bash
./install.sh /path/to/install /path/to/bin
```

## 🔄 Update Dataset

The dataset updates automatically on first run. To manually update:

```bash
cd ~/.../malicious-package-scanner
git -C ./malicious-packages pull
python3 malicious_db_loader.py
```

## 🆚 Single Package vs SBOM

| Use Case | Command | Output |
|---|---|---|
| Quick check | `mallscan requests` | Terminal display |
| PURL format | `mallscan pkg:pypi/requests@2.31.0` | Terminal display |
| Full scan | `mallscan sbom.json` | JSON file + preview |

## 🔗 Integration

### GitHub Actions

```yaml
- name: Scan dependencies
  run: |
    mallscan sbom.json
    HIGH_RISK=$(jq '[.[] | select(.risk_score > 75)] | length' output/sbom-results.json)
    if [ "$HIGH_RISK" -gt 0 ]; then
      echo "❌ Found $HIGH_RISK high-risk packages"
      exit 1
    fi
```

### GitLab CI

```yaml
scan:packages:
  script:
    - mallscan sbom.json
    - jq '.[] | select(.risk_score > 75)' output/sbom-results.json
```
### Jenkins

```
stages {
        stage('Scan-Packages') {
            steps {
                script {
                    echo '📦 Installing Malicious Package Scanner...'
                    sh '''
                        sudo apt-get update
                        sudo apt-get install -y jq git python3 python3-pip
                        
                       echo ' Download and install tool '
                        wget -q https://github.com/YOUR_USERNAME/malicious-package-scanner/releases/download/v2.0/malicious-package scanner.zip
                        unzip -q malicious-package-scanner.zip
                        cd malicious-package-scanner
                        chmod +x install.sh
                        sudo ./install.sh
                        cd ..
                    '''
                   echo '🔎 Scanning for malicious packages...'
                    sh '''
                        mkdir -p ${OUTPUT_DIR}
                        mallscan "${SBOM_FILE}"
                    '''
                }
            }
        }
```

## ❓ FAQ

**Q: Does it block packages?**
A: No, it only warns you. You decide what to do.

**Q: Do I need internet?**
A: First run downloads the dataset (~500MB). After that, works offline.

**Q: How often is the database updated?**
A: OpenSSF updates daily. Dataset auto-updates on each scan.

**Q: What about false positives?**
A: Risk scores are suggestions. Review each result independently.

**Q: How fast is it?**
A: Single package: 1-2 seconds. SBOM (100 packages): ~30 seconds.

## 🔐 What It Does & Doesn't Do

### ✅ Does
- Analyze package names
- Compare against malicious database
- Detect typos/suspicious patterns
- Calculate risk scores
- Work offline (after first download)

### ❌ Doesn't
- Run/execute packages
- Modify your code
- Block packages
- Make decisions for you
- Require constant internet

## 📖 Data Source

Database: [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)

- Maintained by Open Source Security Foundation
- Community-driven vulnerability reports
- Daily updates
- Free to use

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Found a bug? Have a suggestion?

1. Check [CONTRIBUTING.md](CONTRIBUTING.md)
2. Open an issue
3. Submit a pull request

## 🚀 Roadmap

- [ ] Support more ecosystems (Cargo, Maven, Composer)
- [ ] Configuration file support
- [ ] Exclude patterns/whitelist
- [ ] Web dashboard
- [ ] API server mode
- [ ] Docker container

## 📊 Example Workflow

```bash
# 1. Generate SBOM
syft my-project -o json > sbom.json

# 2. Scan for malicious packages
mallscan sbom.json

# 3. Review results
cat output/sbom-results.json | jq '.[] | select(.risk_score > 50)'

# 4. Take action
# - Remove high-risk packages
# - Update dependencies
# - Report findings
```

## 🆘 Troubleshooting

**"mallscan: command not found"**
```bash
# Add to PATH
export PATH="/usr/local/bin:$PATH"
# Or reinstall: sudo ./install.sh
```

**"jq: command not found"**
```bash
sudo apt install jq  # Debian/Ubuntu
brew install jq      # macOS
```

**"Python module not found"**
```bash
pip install -r requirements.txt
```

**"SBOM file not found"**
```bash
# Use absolute path or relative path from current directory
mallscan /full/path/to/sbom.json
```

## 🎉 Getting Started

```bash
# Install
sudo ./install.sh

# Test
mallscan requests

# Scan your project
syft . -o json > sbom.json
mallscan sbom.json
```

That's it! Your dependencies are now scanned for malicious packages. 🚀

---

**Version:** 1.0  
**Author:** Mintu Patel || Application Security Engineer @Abluva
**Last Updated:** April 28, 2026
