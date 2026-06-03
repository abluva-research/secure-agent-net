#!/bin/bash
# ============================================================
# Tenant Cluster Bootstrap Script (Skupper v2)
#
# Description:
#   Bootstraps a tenant cluster for the Abluva hybrid-SaaS platform.
#   Installs cluster-level infrastructure (Skupper, MetalLB) and
#   provisions a tenant namespace with a Skupper site and link.
#
# Usage:
#   ./tenant-start.sh <path/to/token.yaml>
#
# Arguments:
#   token.yaml  - AccessToken YAML file generated from the SaaS cluster.
#                 Contains URL, code, and CA for secure link establishment.
#                 Must be used within the expiration window (default: 15min).
#
# Prerequisites:
#   - kubectl configured with cluster-admin access to the tenant cluster
#   - Token YAML generated from the SaaS cluster (via AccessGrant)
#   - metallb.yaml in the current directory (if no LB configured)
#   - Network connectivity to SaaS cluster on ports 55671, 45671
#   - agent-deployment/agent-deployment.yaml available
#
# Security Notes:
#   - Token files provide access to the application network — handle securely
#   - MetalLB IP pools must be unique per cluster to avoid collisions
#   - The script uses --dry-run=client for idempotent namespace creation
#
# Execution Order:
#   CLUSTER-LEVEL (idempotent — skipped if already present):
#     1. Skupper controller
#     2. Skupper CLI
#     3. MetalLB (only if no LoadBalancer configured)
#
#   TENANT-LEVEL:
#     4. Namespace creation
#     5. Skupper site creation
#     6. Token redemption (cross-cluster link)
#     7. Skupper listeners (control-server, control-client)
#     8. Agent deployment
# ============================================================

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# --- Configuration -----------------------------------------------------------
# Tenant namespace identifier (set by the launcher/provisioner)
NAMESPACE_NAME="<tenant-namespace>"

# Timeouts for waiting on deployments and resources
readonly SKUPPER_TIMEOUT="300s"
readonly METALLB_TIMEOUT="300s"
readonly SITE_TIMEOUT=120    # seconds
readonly LINK_TIMEOUT=120    # seconds
readonly AGENT_TIMEOUT="300s"

# --- Input Validation ---------------------------------------------------------
TOKEN_PATH="${1:-}"

if [ -z "$TOKEN_PATH" ]; then
  echo "Error: Missing required argument."
  echo "Usage: ./tenant-start.sh <path/to/token.yaml>"
  exit 1
fi

if [ ! -f "$TOKEN_PATH" ]; then
  echo "Error: Token file not found: $TOKEN_PATH"
  exit 1
fi

# Validate the token file contains expected Skupper resource kind
if ! grep -q "kind: AccessToken" "$TOKEN_PATH" 2>/dev/null; then
  echo "Warning: '$TOKEN_PATH' may not be a valid AccessToken YAML."
  echo "         Expected 'kind: AccessToken' in the file."
fi

echo "Is a LoadBalancer configured in the cluster? [yes/no]"
read -r IS_LOADBALANCER
IS_LOADBALANCER=$(echo "$IS_LOADBALANCER" | tr '[:upper:]' '[:lower:]')

if [[ "$IS_LOADBALANCER" != "yes" && "$IS_LOADBALANCER" != "no" ]]; then
  echo "Error: Invalid input. Please answer 'yes' or 'no'."
  exit 1
fi

# ============================================================
# [1/8] CLUSTER-LEVEL: Skupper Controller
# Installs the Skupper v2 controller (cluster-scoped).
# The controller manages Site, Connector, Listener, and Link
# custom resources across all namespaces.
# Skipped if the 'skupper' namespace already exists.
# ============================================================
echo ""
echo "============================================================"
echo "[1/8] Skupper Controller"
echo "============================================================"

if kubectl get namespace skupper >/dev/null 2>&1; then
  echo "[SKIP] Skupper controller already installed."
else
  echo "Installing Skupper controller..."
  kubectl apply -f https://skupper.io/install.yaml
fi

echo "Waiting for controller deployment..."
kubectl wait deployment/skupper-controller \
  -n skupper \
  --for=condition=Available \
  --timeout="$SKUPPER_TIMEOUT"

echo "[OK] Skupper controller is available."

# ============================================================
# [2/8] CLUSTER-LEVEL: Skupper CLI
# Installs the Skupper v2 command-line interface.
# Used for site creation, token redemption, and status checks.
# Skipped if 'skupper' command is already in PATH.
# ============================================================
echo ""
echo "============================================================"
echo "[2/8] Skupper CLI"
echo "============================================================"

if command -v skupper >/dev/null 2>&1; then
  echo "[SKIP] Skupper CLI already installed."
else
  echo "Installing Skupper CLI..."
  curl -fL https://skupper.io/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"

  # Persist PATH update for future shell sessions
  if ! grep -q '.local/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
  fi

  # Wait for CLI binary to become available
  cli_wait=0
  until command -v skupper >/dev/null 2>&1; do
    if [ "$cli_wait" -ge 30 ]; then
      echo "Error: Skupper CLI not found after 30s."
      exit 1
    fi
    echo "  Waiting for Skupper CLI..."
    sleep 2
    cli_wait=$((cli_wait + 2))
  done
fi

echo "[OK] Skupper CLI ready."

# ============================================================
# [3/8] CLUSTER-LEVEL: MetalLB
# Provides LoadBalancer service type on bare-metal clusters.
# Assigns external IPs from a configured address pool.
#
# IMPORTANT: Each cluster must have a UNIQUE IP pool to prevent
# GrantServer IP collisions that cause TLS certificate errors
# during token redemption.
#
# Skipped if:
#   - User indicated a LoadBalancer is already configured
#   - MetalLB namespace already exists
# ============================================================
echo ""
echo "============================================================"
echo "[3/8] MetalLB"
echo "============================================================"

if [ "$IS_LOADBALANCER" = "yes" ]; then
  echo "[SKIP] External LoadBalancer already configured."
elif kubectl get namespace metallb-system >/dev/null 2>&1; then
  echo "[SKIP] MetalLB already installed."
else
  # Verify metallb.yaml exists before installing
  if [ ! -f "metallb.yaml" ]; then
    echo "Error: metallb.yaml not found in current directory."
    echo "       This file must define an IPAddressPool with a unique IP range."
    exit 1
  fi

  echo "Installing MetalLB..."
  kubectl apply -f \
    https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml

  echo "Waiting for MetalLB controller..."
  kubectl wait deployment/controller \
    -n metallb-system \
    --for=condition=Available \
    --timeout="$METALLB_TIMEOUT"

  # Apply the IP address pool and L2 advertisement
  kubectl apply -f metallb.yaml

  echo "[OK] MetalLB installed and configured."
fi

# ============================================================
# [4/8] TENANT-LEVEL: Namespace
# Creates the tenant namespace using --dry-run for idempotency.
# Sets the current kubectl context to the new namespace.
# ============================================================
echo ""
echo "============================================================"
echo "[4/8] Tenant Namespace: $NAMESPACE_NAME"
echo "============================================================"

kubectl create namespace "$NAMESPACE_NAME" --dry-run=client -o yaml | kubectl apply -f -
kubectl config set-context --current --namespace "$NAMESPACE_NAME"

echo "[OK] Namespace ready. Context set to: $NAMESPACE_NAME"

# ============================================================
# [5/8] TENANT-LEVEL: Skupper Site
# Creates a Skupper site in the tenant namespace.
# This deploys the skupper-router pod which handles cross-cluster
# traffic via AMQP over mutual TLS.
# ============================================================
echo ""
echo "============================================================"
echo "[5/8] Skupper Site"
echo "============================================================"

echo "Creating Skupper site: $NAMESPACE_NAME"
skupper site create "$NAMESPACE_NAME"

echo "Waiting for site to become ready..."
site_elapsed=0
until kubectl get site "$NAMESPACE_NAME" -o jsonpath='{.status.status}' 2>/dev/null | grep -q "Ready"; do
  if [ "$site_elapsed" -ge "$SITE_TIMEOUT" ]; then
    echo "Error: Site not ready after ${SITE_TIMEOUT}s."
    echo "  Troubleshooting:"
    echo "    kubectl get site $NAMESPACE_NAME -o yaml"
    echo "    kubectl get pods -l app=skupper-router -n $NAMESPACE_NAME"
    echo "    Ensure NetworkPolicy allows egress to the K8s API server."
    exit 1
  fi
  echo "  Site pending... (${site_elapsed}/${SITE_TIMEOUT}s)"
  sleep 5
  site_elapsed=$((site_elapsed + 5))
done

echo "[OK] Skupper site is ready."

# ============================================================
# [6/8] TENANT-LEVEL: Token Redemption (Link)
# Redeems the AccessToken YAML to establish a mutual-TLS link
# between this tenant cluster and the SaaS cluster.
#
# The token contains:
#   - GrantServer URL (on SaaS cluster)
#   - One-time code
#   - CA certificate for TLS verification
#
# After redemption, a Link resource is created that maintains
# the persistent connection between skupper-routers.
# ============================================================
echo ""
echo "============================================================"
echo "[6/8] Token Redemption (Link)"
echo "============================================================"

echo "Redeeming token: $TOKEN_PATH"
skupper token redeem "$TOKEN_PATH"

echo "Waiting for link to become active..."
link_elapsed=0
until skupper link status 2>/dev/null | grep -q "Ready"; do
  if [ "$link_elapsed" -ge "$LINK_TIMEOUT" ]; then
    echo "Warning: Link not ready after ${LINK_TIMEOUT}s."
    echo "  Troubleshooting:"
    echo "    kubectl get links -n $NAMESPACE_NAME"
    echo "    kubectl get accesstokens -n $NAMESPACE_NAME -o yaml"
    echo "    Verify MetalLB IP pools don't collide between clusters."
    echo "    Alternative: use 'skupper link generate' on the SaaS cluster."
    echo ""
    echo "  Continuing setup — link may still establish."
    break
  fi
  echo "  Waiting for link... (${link_elapsed}/${LINK_TIMEOUT}s)"
  sleep 5
  link_elapsed=$((link_elapsed + 5))
done

if skupper link status 2>/dev/null | grep -q "Ready"; then
  echo "[OK] Cross-cluster link established."
else
  echo "[WARN] Link not yet confirmed. Check status manually."
fi

# ============================================================
# [7/8] TENANT-LEVEL: Skupper Listeners
# Creates listeners that expose remote services (from the SaaS
# cluster) as local ClusterIP services in this namespace.
#
# Each listener matches a Connector on the SaaS cluster by
# routingKey. Traffic is routed through the Skupper link.
#
# Listeners created:
#   - control-client:80  (routingKey: control-client)
#   - control-server:5001 (routingKey: control-server)
# ============================================================
echo ""
echo "============================================================"
echo "[7/8] Skupper Listeners"
echo "============================================================"

echo "Creating listeners for remote services..."
skupper listener create control-client --host control-client --port 80 --routing-key control-client
skupper listener create control-server --host control-server --port 5001 --routing-key control-server

echo "[OK] Listeners created."
echo "  Available services in this namespace:"
echo "    - control-client:80   → SaaS control-client"
echo "    - control-server:5001 → SaaS control-server API"

# ============================================================
# [8/8] TENANT-LEVEL: Agent Deployment
# Deploys the Abluva agent (kube-launcher) which:
#   - Polls control-server for tasks
#   - Applies Kubernetes manifests on the tenant cluster
#   - Reports task status back to the SaaS platform
#
# The agent uses the Skupper listener (control-server:5001)
# to communicate with the SaaS cluster.
# ============================================================
echo ""
echo "============================================================"
echo "[8/8] Agent Deployment"
echo "============================================================"

if [ ! -f "agent-deployment/agent-deployment.yaml" ]; then
  echo "Warning: agent-deployment/agent-deployment.yaml not found."
  echo "         Skipping agent deployment."
else
  echo "Deploying Abluva agent..."
  kubectl apply -f agent-deployment/agent-deployment.yaml

  echo "Waiting for agent to be available..."
  kubectl wait deployment/abluva-agent \
    -n "$NAMESPACE_NAME" \
    --for=condition=Available \
    --timeout="$AGENT_TIMEOUT"

  echo "[OK] Agent deployed and running."
fi

# ============================================================
# Setup Complete — Summary
# ============================================================
echo ""
echo "============================================================"
echo "  TENANT SETUP COMPLETE"
echo "============================================================"
echo ""
echo "  Cluster:        $(kubectl config current-context)"
echo "  Namespace:      $NAMESPACE_NAME"
echo "  Skupper Site:   $(kubectl get site "$NAMESPACE_NAME" -o jsonpath='{.status.status}' 2>/dev/null || echo 'Unknown')"
echo "  Sites in Net:   $(kubectl get site "$NAMESPACE_NAME" -o jsonpath='{.status.sitesInNetwork}' 2>/dev/null || echo 'Unknown')"
echo "  Link Status:    $(skupper link status 2>/dev/null | grep -o 'Ready' | head -1 || echo 'Pending')"
echo ""
echo "  Services (via Skupper):"
echo "    control-client:80   → SaaS web UI"
echo "    control-server:5001 → SaaS API"
echo ""
echo "  Verify connectivity:"
echo "    kubectl exec -it deployment/abluva-agent -n $NAMESPACE_NAME -- \\"
echo "      curl --max-time 10 http://control-server:5001/api/v1/control/tenants"
echo ""
echo "============================================================"
