#!/bin/bash
# =============================================================================
# Ghidra Installation Script for Linux/macOS
# =============================================================================
# This script downloads and installs Ghidra
# Usage: ./scripts/install-ghidra.sh [-v VERSION] [-d INSTALL_DIR]

set -e

# Default values
VERSION="11.4.3"
INSTALL_DIR="/opt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
while getopts "v:d:h" opt; do
    case $opt in
        v) VERSION="$OPTARG" ;;
        d) INSTALL_DIR="$OPTARG" ;;
        h)
            echo "Usage: $0 [-v VERSION] [-d INSTALL_DIR]"
            echo "  -v VERSION     Ghidra version (default: 11.4.3)"
            echo "  -d INSTALL_DIR Installation directory (default: /opt)"
            exit 0
            ;;
        \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    esac
done

echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  Ghidra ${VERSION} Installation Script${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""

# Check for required tools
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is required but not installed.${NC}"
        exit 1
    fi
}

check_command curl
check_command unzip

# Step 1: Create installation directory
echo -e "${YELLOW}[1/5] Creating installation directory...${NC}"
if [ ! -d "$INSTALL_DIR" ]; then
    sudo mkdir -p "$INSTALL_DIR"
    echo -e "  ${GREEN}Created: $INSTALL_DIR${NC}"
else
    echo -e "  ${GREEN}Already exists: $INSTALL_DIR${NC}"
fi

# Step 2: Get download URL from GitHub API
echo -e "${YELLOW}[2/5] Fetching release information from GitHub...${NC}"
RELEASES_API="https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_${VERSION}_build"

DOWNLOAD_URL=$(curl -s "$RELEASES_API" | grep -o '"browser_download_url": "[^"]*\.zip"' | head -1 | cut -d'"' -f4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo -e "  ${YELLOW}Could not fetch from API, trying known patterns...${NC}"
    
    # Try recent dates
    for DATE in $(date +%Y%m%d) $(date -d "yesterday" +%Y%m%d 2>/dev/null || date -v-1d +%Y%m%d 2>/dev/null) "20251204" "20251203"; do
        TEST_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VERSION}_build/ghidra_${VERSION}_PUBLIC_${DATE}.zip"
        if curl --output /dev/null --silent --head --fail "$TEST_URL"; then
            DOWNLOAD_URL="$TEST_URL"
            break
        fi
    done
fi

if [ -z "$DOWNLOAD_URL" ]; then
    echo ""
    echo -e "${RED}ERROR: Could not find Ghidra download URL automatically.${NC}"
    echo ""
    echo -e "${YELLOW}Please download manually from:${NC}"
    echo -e "  ${CYAN}https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_${VERSION}_build${NC}"
    echo ""
    echo -e "${YELLOW}Then extract to: $INSTALL_DIR${NC}"
    exit 1
fi

FILENAME=$(basename "$DOWNLOAD_URL")
echo -e "  ${GREEN}Found: $FILENAME${NC}"

# Step 3: Download Ghidra
DOWNLOAD_PATH="/tmp/$FILENAME"
echo -e "${YELLOW}[3/5] Downloading Ghidra ($FILENAME)...${NC}"
echo -e "  URL: $DOWNLOAD_URL"
echo -e "  This may take several minutes (~400MB)..."

curl -L -o "$DOWNLOAD_PATH" "$DOWNLOAD_URL" --progress-bar

FILE_SIZE=$(du -h "$DOWNLOAD_PATH" | cut -f1)
echo -e "  ${GREEN}Downloaded: $FILE_SIZE${NC}"

# Step 4: Extract Ghidra
echo -e "${YELLOW}[4/5] Extracting Ghidra to $INSTALL_DIR...${NC}"
echo -e "  This may take a minute..."

sudo unzip -q -o "$DOWNLOAD_PATH" -d "$INSTALL_DIR"

# Find extracted directory
GHIDRA_DIR=$(find "$INSTALL_DIR" -maxdepth 1 -type d -name "ghidra_*" | sort -r | head -1)

if [ -z "$GHIDRA_DIR" ]; then
    echo -e "${RED}Error: Could not find extracted Ghidra directory${NC}"
    exit 1
fi

echo -e "  ${GREEN}Extracted to: $GHIDRA_DIR${NC}"

# Make scripts executable
sudo chmod +x "$GHIDRA_DIR/ghidraRun"
sudo chmod +x "$GHIDRA_DIR/support/analyzeHeadless"

# Step 5: Set environment variable
echo -e "${YELLOW}[5/5] Setting environment variable...${NC}"

# Detect shell config file
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

# Add to shell config if not already present
if ! grep -q "GHIDRA_INSTALL_DIR" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# Ghidra installation path" >> "$SHELL_RC"
    echo "export GHIDRA_INSTALL_DIR=\"$GHIDRA_DIR\"" >> "$SHELL_RC"
    echo -e "  ${GREEN}Added to $SHELL_RC${NC}"
else
    # Update existing
    sed -i.bak "s|export GHIDRA_INSTALL_DIR=.*|export GHIDRA_INSTALL_DIR=\"$GHIDRA_DIR\"|" "$SHELL_RC"
    echo -e "  ${GREEN}Updated in $SHELL_RC${NC}"
fi

# Set for current session
export GHIDRA_INSTALL_DIR="$GHIDRA_DIR"
echo -e "  ${GREEN}GHIDRA_INSTALL_DIR = $GHIDRA_DIR${NC}"

# Cleanup
echo ""
echo "Cleaning up temporary files..."
rm -f "$DOWNLOAD_PATH"

# Summary
echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "Ghidra installed to: ${CYAN}$GHIDRA_DIR${NC}"
echo ""
echo -e "${YELLOW}Environment variable set:${NC}"
echo -e "  GHIDRA_INSTALL_DIR = $GHIDRA_DIR"
echo ""
echo -e "${YELLOW}To use in current terminal, run:${NC}"
echo -e "  source $SHELL_RC"
echo ""
echo -e "${YELLOW}To launch Ghidra GUI:${NC}"
echo -e "  $GHIDRA_DIR/ghidraRun"
echo ""

# Check for Java
echo -e "${YELLOW}Checking Java installation...${NC}"
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -1)
    echo -e "  ${GREEN}Java found: $JAVA_VERSION${NC}"
else
    echo -e "  ${RED}WARNING: Java not found!${NC}"
    echo -e "  ${YELLOW}Ghidra requires JDK 17 or later.${NC}"
    echo -e "  ${CYAN}Install with: sudo apt install openjdk-17-jdk (Ubuntu/Debian)${NC}"
    echo -e "  ${CYAN}Or download from: https://adoptium.net/${NC}"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
