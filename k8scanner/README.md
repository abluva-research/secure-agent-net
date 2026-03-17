# Kubernetes Security Scanner

A **modular Kubernetes security scanning script** that automates cluster, container, and infrastructure security analysis using multiple open-source security tools.

This tool runs **cluster security checks, vulnerability scans, SBOM generation, and IaC security analysis** and produces **structured JSON reports and logs**, including a **single aggregated master report**.

---

## Features

* **Cluster Security Scanning**

  * Runs kube-hunter passive and active scans

* **CIS Benchmark Checks**

  * Runs kube-bench against the cluster

* **Infrastructure as Code (IaC) Scanning**

  * Uses terrascan to analyze Kubernetes manifests, Terraform, and other IaC files

* **Container Image Analysis**

  * Automatically extracts container images running in the cluster
  * Generates **SBOMs using Syft**
  * Scans SBOMs for vulnerabilities using **Grype**

* **Namespace-Based Scanning**

  * Select specific namespaces for container scanning

* **Automated Authentication**

  * Supports existing kubeconfig
  * Supports API server + bearer token authentication

* **Structured Output**

  * JSON reports for every tool
  * Per-namespace SBOM and vulnerability reports
  * Aggregated master report

* **Safe Execution**

  * Automatic cleanup using trap handlers
  * Temporary kubeconfig removed after scan

---

## Tools Used

This scanner integrates the following open-source tools:

| Tool        | Purpose                                 |
| ----------- | --------------------------------------- |
| kube-hunter | Kubernetes penetration testing          |
| kube-bench  | CIS Kubernetes benchmark scanning       |
| terrascan   | IaC security misconfiguration detection |
| syft        | SBOM generation                         |
| grype       | Vulnerability scanning from SBOM        |

---

## Architecture

The script performs the following scanning workflow:

```
User Input
   │
   ▼
Authentication Setup
   │
   ▼
Cluster Scanning
   ├── kube-hunter (passive + active)
   ├── kube-bench
   │
   ▼
Infrastructure Scanning
   └── terrascan
   │
   ▼
Container Analysis
   ├── Extract images from Kubernetes resources
   ├── Generate SBOM (syft)
   └── Vulnerability scan (grype)
   │
   ▼
Report Aggregation
   └── master-report.json
```

---

## Requirements

Ensure the following are installed:

* Docker
* kubectl
* jq
* Bash

Verify installation:

```bash
docker --version
kubectl version --client
jq --version
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/k8s-security-scanner.git
cd k8s-security-scanner
```

Make the script executable:

```bash
chmod +x k8scanner.sh
```

---

## Usage

Run the script:

```bash
./k8scanner.sh
```

The script will start an **interactive setup**.

---

## Interactive Setup

You will be asked for:

### 1. Output Directory

Default:

```
./scans
```

All scan results will be stored in a timestamped folder.

Example:

```
scans/16-03-2026_12-00-15/
```

---

### 2. Aggregated Report

Option to generate a **master report combining all scanners**.

```
Create aggregated master report at end? (y/N)
```

---

### 3. IaC Folder

Directory containing:

* Kubernetes YAML
* Helm manifests
* Terraform
* IaC files

Default:

```
Current directory
```

---

### 4. Kubernetes Authentication

Choose one:

```
1) Existing kubeconfig
2) API Server + Bearer Token
```

#### Option 1 – Existing kubeconfig

Uses your current context:

```
~/.kube/config
```

#### Option 2 – API Server + Token

Provide:

```
API Server URL
Bearer Token
```

The script will create a **temporary kubeconfig automatically**.

---

### 5. Namespace Selection

Select namespaces for **container image scanning**.

Example:

```
default,production,staging
```

Default:

```
default
```

---

## Output Structure

Example:

```
scans/
└── 16-03-2026_12-00-15/
    ├── kube-hunter-passive.json
    ├── kube-hunter-passive.log
    ├── kube-hunter-active.json
    ├── kube-hunter-active.log
    ├── kube-bench.json
    ├── terrascan.json
    │
    ├── sbom/
    │   └── default/
    │       ├── nginx_latest.json
    │       ├── grype-nginx_latest.json
    │
    ├── syft-sbom-default.json
    ├── grype-default.json
    │
    └── master-report.json
```

---

## Report Types

### kube-hunter Reports

| File                     | Description                    |
| ------------------------ | ------------------------------ |
| kube-hunter-passive.json | Passive cluster reconnaissance |
| kube-hunter-active.json  | Active vulnerability probing   |

---

### kube-bench

```
kube-bench.json
```

Contains **CIS Kubernetes Benchmark results**.

---

### Terrascan

```
terrascan.json
```

Detects:

* insecure Kubernetes configurations
* Terraform misconfigurations
* IaC policy violations

---

### SBOM Reports

Generated using **Syft**.

Example:

```
syft-sbom-default.json
```

Contains complete dependency inventory for container images.

---

### Vulnerability Reports

Generated using **Grype**.

Example:

```
grype-default.json
```

Includes:

* CVE IDs
* severity levels
* vulnerable packages

---

### Master Report

If enabled, a **single aggregated JSON report** is generated.

```
master-report.json
```

Contains:

```
{
  kube-hunter-passive: {},
  kube-hunter-active: {},
  kube-bench: {},
  terrascan: {},
  namespace-results: {
      default: {
          syft: {},
          grype: {}
      }
  }
}
```

---

## Cleanup

The script automatically performs cleanup:

* Removes temporary kubeconfig
* Removes temporary Docker containers

This is handled using a **trap exit handler**.

---

## Example Scan

Run the scanner:

```bash
./k8scanner.sh
```

Example input:

```
Output directory: ./scans
Create master report: y
IaC folder: ./k8s-manifests
Authentication: existing kubeconfig
Namespaces: default,production
```

---

## Security Use Cases

This tool can be used for:

* Kubernetes penetration testing
* DevSecOps pipeline security validation
* Container vulnerability analysis
* Infrastructure misconfiguration detection
* Red team reconnaissance
* Compliance audits

---

## Future Improvements

Possible enhancements:

* Trivy integration
* Falco runtime security checks
* Helm chart scanning
* HTML reporting dashboard
* CI/CD integration
* Parallel scanning

---

## Disclaimer

This tool is intended **only for security testing on systems you own or have permission to test**.

Unauthorized scanning may violate laws and regulations.

---

## License

MIT License

---
