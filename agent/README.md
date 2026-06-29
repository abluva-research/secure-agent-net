# Tenant Cluster Setup Guide

## Overview

Connect your Kubernetes cluster to the Abluva platform in minutes. This guide walks you through generating a token from the platform UI and running a single script to set up the secure connection.

---

## Step 1: Generate Token

1. Log in to the **Abluva Tenant App**
2. Navigate to the **Environments** page
3. Click **Generate Skupper Token**
4. Download or copy the token and save it as a file (e.g., `token.yaml`)

> **Note**: The token is single-use and expires after a limited time. Complete the setup promptly after generating it.

---

## Step 2: Get Namespace, Tenant ID, Environment ID, and SAAS-API-KEY

### Namespace and Environment ID
1. In the same **Environments** page, click the dropdown arrow on your environment
2. Under the **Details** section, you will find:
   - **Namespace** 
   - **Environment ID**

### SAAS-API-KEY
1. In the **Environments** page, click the drop-down key button and select Generate API key on your environment
2. It Generates the key and displays it for 15 seconds

> **Note**:When Needed ROTATE the api key by clicking Rotate API Key Button. 

### Tenant ID
1. In the **Tenants** Page, Click your tenant and get the Tenant ID.

Save these values — you'll need them in Step 5.

---

## Step 3: Prerequisites

Ensure the following on the machine where you'll run the setup:

- [ ] **Kubernetes cluster** with `cluster-admin` access
- [ ] **kubectl** installed and configured to point to your cluster
- [ ] **curl** installed
- [ ] **Network connectivity** — your cluster nodes must be able to reach the Abluva platform on TCP ports **443**, **55671**, and **45671**
- [ ] **Token file** saved from Step 1
- [ ] **Namespace, Environment ID, SAAS-API-KEY, TenantID** from Step 2

---

## Step 4: Clone the Setup Repository

```bash
git clone https://github.com/abluva-research/secure-agent-net.git
cd agent
```

---

## Step 5: Configure Agent Deployment

Open `agent-deployment.yaml` and replace the placeholders with your actual values:

```yaml
env:
  - name: SAAS_API_KEY
    value: "<your-saas-api-key>"
  - name: X_ABLV_Tenant_ID
    value: "<your-tenant-id>"
  - name: X_ABLV_Environment_ID
    value: "<your-environment-id>"
  - name: X_ABLV_Principal
    value: "<PRINCIPAL_PLACEHOLDER>"
```

Also update the namespace in the YAML metadata to match your tenant namespace.

---

## Step 6: Run the Setup Script

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

| Step | Action | Notes |
|------|--------|-------|
| 1 | Install Skupper controller | Skipped if already installed |
| 2 | Install MetalLB | Only if no LoadBalancer configured |
| 3 | Create tenant namespace | Idempotent (format: `<tenant-id>-<env-id>`) |
| 4 | Create Skupper Site | Deploys skupper-router in your namespace |
| 5 | Redeem token | Establishes mTLS link to the Abluva platform |
| 6 | Create Listeners | Makes platform services accessible locally as `control-server:80` and `control-client:80` |
| 7 | Deploy agent | Your agent connects to control-server through the secure link |

---

## Step 7: Verify Setup

```bash
NAMESPACE=<your-tenant-namespace>

# Check all pods are running
kubectl get pods -n $NAMESPACE

# Verify Skupper site (should show Ready)
kubectl get site -n $NAMESPACE

# Verify link is active (should show Ready)
kubectl get links -n $NAMESPACE

# Verify listeners exist
kubectl get listener -n $NAMESPACE

# Verify control-server service was created by listener
kubectl get svc control-server -n $NAMESPACE

```

A JSON response with tenant data confirms the setup is working.

---

## Step 8: Register Resource in Platform

After the agent is deployed and verified:

1. Navigate to **Resources Tab** → **Add Resource**
2. Select your **Tenant**
3. Give a **Resource Name**
4. Choose Resource Type: `agent#https`
5. Click **Next**
6. Choose **Credentials** as Authentication Type
7. In the JSON box, add:

```json
{
  "base_url": "agent.<namespace>.svc.cluster.local:5004",
  "endpoint": "/api/v1/launcher/create"
}
```

Replace `<namespace>` with your tenant namespace.

---

## Service Endpoint Available

Once connected, your agent can call these service:

| Service | URL from your cluster | Purpose |
|---------|----------------------|---------|
| Control Server | `http://control-server:80` | Platform API (tasks, tenants, environments, subscriptions) |

---

## Troubleshooting

### Token redemption fails with TLS error

**Cause**: MetalLB IP collision between your cluster and the platform.

**Fix**: Ensure your MetalLB uses a unique IP range that doesn't overlap with the platform cluster (172.16.1.200-219). Contact Abluva support if unsure.

### Site stuck in Pending

**Cause**: The skupper-router pod can't reach the Kubernetes API server.

**Fix**: Verify API server access:
```bash
kubectl get endpoints kubernetes -n default
```

### Agent image pull error

**Cause**: Your cluster can't reach the container registry.

**Fix**: Contact Abluva support for alternative image delivery or configure registry trust.

### Link shows Ready but agent can't reach control-server

**Cause**: Listeners may not be created, or the control-server service doesn't exist.

**Fix**:
```bash
# Check listeners
kubectl get listener -n $NAMESPACE

# Check services (control-server should exist)
kubectl get svc -n $NAMESPACE

# Check link has matching connector
kubectl describe listener control-server -n $NAMESPACE
# STATUS should be Ready, HAS MATCHING CONNECTOR should be true
```

### Request hangs (timeout)

**Cause**: NetworkPolicy on the SaaS cluster may be blocking traffic, or skupper-router can't reach the proxy.

**Fix**: Contact Abluva support — this is a platform-side issue.

---

## Support

If you encounter issues, contact Abluva support.
```
