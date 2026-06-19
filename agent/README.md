# Tenant Cluster Setup Guide

## Overview

Connect your Kubernetes cluster to the Abluva platform in minutes. This guide walks you through generating a token from the platform UI and running a single script to set up the secure connection.

---

## Step 1: Generate Token

1. Log in to the **Abluva Tenant App**
2. Navigate to the **Environments** page
3. Click **Generate Skupper Token**
4. Download or copy the token and save it as a file (e.g., `token.yaml`)
5. Namespace will be displayed in the UI itself please copy and use it while setup.
6. Copy the token displayed in the UI and later before running the script.
7. Get the tenantId from tenants page->click eye button->get the ID.Get the environmentId from environments page->click eye button->get the ID. 
8. Replace namespace,token,tenantId,environmentId to their respective placeholers in the agent-deployment.yaml.

> **Note**: The token expires after a limited time. Complete the setup promptly after generating it.

---

## Step 2: Prerequisites

Ensure the following on the machine where you'll run the setup:

- [ ] **Kubernetes cluster** with `cluster-admin` access
- [ ] **kubectl** installed and configured to point to your cluster
- [ ] **curl** installed
- [ ] **Network connectivity** — your cluster nodes must be able to reach the Abluva platform on TCP ports **55671** and **45671**
- [ ] **Token file, Namespace, Token** saved from Step 1

---

## Step 3: Clone the Setup Repository

```bash
git clone https://github.com/abluva-research/secure-agent-net.git
cd agent
```

---

## Step 4: Run the Setup Script

```bash
chmod +x tenant-start.sh
./tenant-start.sh <path/to/token.yaml>
```

**Example:**
```bash
./tenant-start.sh ./token.yaml
```

The script will prompt:
```
Is a LoadBalancer configured in the cluster? [yes/no]
```

- Answer **yes** if your cluster already has a LoadBalancer provider (cloud provider LB, existing MetalLB, etc.)
- Answer **no** if running on bare-metal without a LoadBalancer — the script will install MetalLB automatically

---

## What the Script Does

The script automatically performs the following:

| Step | Action | Notes |
|------|--------|-------|
| 1 | Install Skupper controller | Skipped if already installed |
| 2 | Install Skupper CLI | Skipped if already installed |
| 3 | Install MetalLB | Only if no LoadBalancer configured |
| 4 | Create tenant namespace | Idempotent |
| 5 | Create Skupper site | Deploys the skupper-router |
| 6 | Redeem token | Establishes secure link to the Abluva platform |
| 7 | Create listeners | Makes platform services accessible locally |
| 8 | Deploy agent | Connects to the Abluva control plane |

---

## Step 5: Verify

After the script completes, verify the connection:

```bash
kubectl exec -it deployment/agent -n <namespace> -- \
  curl --max-time 10 http://control-server:80/api/v1/control/tenants
```

A JSON response with tenant data confirms the setup is working.

You can also check:
```bash
# Site status (should show SITES IN NETWORK: 2)
kubectl get site -n <namespace>

# Link status (should show Ready)
skupper link status --namespace <namespace>

# All pods running
kubectl get pods -n <namespace>
```

---

After deploying the agent create a resource under Resources Tab->Add Resource->Select Tenant->Give any Resource Name->Choose Resource Type as "agent#https"->Next->Choose Credentials as Authentication Type->In the JSON box add the url as 
{
  "base_url": "agent.namespace.svc.cluster.local:5004",
  "endpoint": "/api/v1/launcher/create"
}

## Troubleshooting

### Token redemption fails with TLS error

**Cause**: MetalLB IP collision between your cluster and the platform.

**Fix**: Ensure your `metallb.yaml` uses a unique IP range that doesn't overlap with the platform cluster. Contact Abluva support if unsure.

**Alternative**: Request a link file from Abluva support instead of using a token.

### Site stuck in Pending

**Cause**: The skupper-router pod can't reach the Kubernetes API server.

**Fix**: Find your API server endpoint and ensure network access:
```bash
kubectl get endpoints kubernetes -n default
```

### Agent image pull error

**Cause**: Your cluster can't reach the container registry.

**Fix**: Contact Abluva support for alternative image delivery options or configure your cluster to trust the registry.

### Link shows Ready but agent can't reach control-server

**Fix**: Check listeners exist:
```bash
kubectl get listeners -n <namespace>
kubectl get svc control-server -n <namespace>
```

---

## Security

- All cross-cluster traffic is encrypted via **mutual TLS** (managed automatically by Skupper)
- The agent has **namespace-scoped permissions only** — it cannot access other namespaces on your cluster
- The token is single-use and time-limited
- No inbound ports need to be opened on your cluster — the link is established outbound

---

## Support

If you encounter issues during setup, contact Abluva support with:
- Output of `kubectl get site -n <namespace> -o yaml`
- Output of `kubectl get links -n <namespace> -o yaml`
- Output of `kubectl get pods -n <namespace>`
