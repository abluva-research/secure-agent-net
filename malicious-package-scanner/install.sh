#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="${1:-/usr/local/lib/malicious-package-scanner}"
BIN_DIR="${2:-/usr/local/bin}"

echo -e "${BLUE}Malicious Package Scanner - Installation${NC}"
echo ""

# Check if we need sudo (system-wide install)
if [[ "$INSTALL_DIR" == /usr/local/* ]] && [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
    echo -e "${RED}[!] System-wide installation requires sudo${NC}"
    echo "Re-running with elevated privileges..."
    sudo "$0" "$INSTALL_DIR" "$BIN_DIR"
    exit $?
fi

# Check if we need sudo for BIN_DIR
if [ ! -w "$(dirname "$BIN_DIR")" ]; then
    echo -e "${RED}[!] Binary directory requires sudo${NC}"
    echo "Re-running with elevated privileges..."
    sudo "$0" "$INSTALL_DIR" "$BIN_DIR"
    exit $?
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" || { echo -e "${RED}[!] Failed to create directory${NC}"; exit 1; }

# Copy files
echo "Copying application files..."
cp malicious_db_loader.py "$INSTALL_DIR/" || { echo -e "${RED}[!] Failed to copy malicious_db_loader.py${NC}"; exit 1; }
cp risk_engine.py "$INSTALL_DIR/" || { echo -e "${RED}[!] Failed to copy risk_engine.py${NC}"; exit 1; }
cp mps.sh "$INSTALL_DIR/" || { echo -e "${RED}[!] Failed to copy mps.sh${NC}"; exit 1; }
cp requirements.txt "$INSTALL_DIR/" || { echo -e "${RED}[!] Failed to copy requirements.txt${NC}"; exit 1; }
cp README.md "$INSTALL_DIR/" || { echo -e "${RED}[!] Failed to copy README.md${NC}"; exit 1; }

# Make scripts executable
chmod +x "$INSTALL_DIR/mps.sh"
chmod +x "$INSTALL_DIR/malicious_db_loader.py"
chmod +x "$INSTALL_DIR/risk_engine.py"

# Create bin directory if it doesn't exist
mkdir -p "$BIN_DIR"

# Create wrapper script in bin directory
cat > "$BIN_DIR/mallscan" << 'WRAPPER'
#!/bin/bash
INSTALL_DIR="$(dirname "$(readlink -f "$0")")/../lib/malicious-package-scanner"
exec "$INSTALL_DIR/mps.sh" "$@"
WRAPPER

chmod +x "$BIN_DIR/mallscan"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -q -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || pip3 install -q -r "$INSTALL_DIR/requirements.txt"

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "You can now run the scanner from anywhere:"
echo "  mallscan /path/to/sbom.json"
echo "  mallscan requests"
echo "  mallscan pkg:pypi/requests@2.31.0"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Executable location: $BIN_DIR/mallscan"
echo ""
echo -e "${GREEN}✓ Ready to use!${NC}"
