#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="${1:-/usr/local/lib/malicious-package-scanner}"
BIN_DIR="${2:-/usr/local/bin}"

echo -e "${BLUE}Malicious Package Scanner - Uninstall${NC}"
echo ""

# Check if installed
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${RED}[!] Installation not found at: $INSTALL_DIR${NC}"
    exit 1
fi

# Confirm uninstall
echo -e "${YELLOW}This will remove:${NC}"
echo "  Directory: $INSTALL_DIR"
echo "  Command: $BIN_DIR/mallscan"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

# Check if we need sudo
if [ ! -w "$INSTALL_DIR" ]; then
    echo -e "${RED}[!] Requires sudo for uninstall${NC}"
    echo "Re-running with elevated privileges..."
    sudo "$0" "$INSTALL_DIR" "$BIN_DIR"
    exit $?
fi

# Remove installation directory
echo "Removing installation directory..."
rm -rf "$INSTALL_DIR"

# Remove command symlink
if [ -f "$BIN_DIR/mallscan" ]; then
    echo "Removing command: $BIN_DIR/mallscan"
    rm -f "$BIN_DIR/mallscan"
fi

echo ""
echo -e "${GREEN}✓ Uninstall complete!${NC}"
echo ""
echo "The following were removed:"
echo "  ✓ Installation directory"
echo "  ✓ mallscan command"
echo ""
echo -e "${BLUE}To reinstall, run: ./install.sh${NC}"
