#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="${1:-/usr/local/lib/malicious-package-scanner}"
BIN_DIR="${2:-/usr/local/bin}"

echo -e "${BLUE}Malicious Package Scanner - Installation${NC}"
echo ""

# Check if running with sudo for system-wide install
if [ "$INSTALL_DIR" = "/usr/local/lib/mps" ] && [ ! -w "$(dirname "$BIN_DIR")" ]; then
    echo "System-wide installation requires sudo. Re-running with elevated privileges..."
    sudo "$0" "$INSTALL_DIR" "$BIN_DIR"
    exit 0
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy files
echo "Copying application files..."
cp malicious_db_loader.py "$INSTALL_DIR/"
cp risk_engine.py "$INSTALL_DIR/"
cp mps.sh "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp README.md "$INSTALL_DIR/"

# Make scripts executable
chmod +x "$INSTALL_DIR/mps.sh"
chmod +x "$INSTALL_DIR/malicious_db_loader.py"
chmod +x "$INSTALL_DIR/risk_engine.py"

# Create wrapper script in bin directory
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/mps" << 'EOF'
#!/bin/bash
INSTALL_DIR="$(dirname "$(readlink -f "$0")")/../lib/malicious-package-scanner"
exec "$INSTALL_DIR/mps.sh" "$@"
EOF

chmod +x "$BIN_DIR/mps"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -q -r "$INSTALL_DIR/requirements.txt" || pip3 install -q -r "$INSTALL_DIR/requirements.txt"

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "You can now run the scanner from anywhere:"
echo "  mallscan /path/to/sbom.json"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Executable location: $BIN_DIR/mallscan"