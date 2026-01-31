#!/bin/bash
# Grimbard Security Agent - Initialization Script
# This script runs when a grimbard sub-agent starts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Initializing Grimbard Security Agent..."

# Create output directory structure
OUTPUT_DIR="${GRIMBARD_OUTPUT_DIR:-./grimbard-security-review}"
mkdir -p "$OUTPUT_DIR/sarif"
mkdir -p "$OUTPUT_DIR/reports"
mkdir -p "$OUTPUT_DIR/findings"
mkdir -p "$OUTPUT_DIR/logs"

echo "Output directory: $OUTPUT_DIR"

# Check for required tools
check_tool() {
    local tool=$1
    local required=$2
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[OK]${NC} $tool found"
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}[MISSING]${NC} $tool not found (required)"
            return 1
        else
            echo -e "${YELLOW}[OPTIONAL]${NC} $tool not found"
            return 0
        fi
    fi
}

echo ""
echo "Checking security tools availability..."
echo "----------------------------------------"

# Required tools
MISSING_REQUIRED=0
check_tool "opengrep" "optional" || check_tool "semgrep" "optional" || { echo -e "${YELLOW}[WARN]${NC} Neither opengrep nor semgrep found"; }
check_tool "gitleaks" "optional" || MISSING_REQUIRED=1
check_tool "git" "required" || MISSING_REQUIRED=1

# Optional tools
check_tool "noir" "optional"
check_tool "kics" "optional"
check_tool "osv-scanner" "optional"
check_tool "depscan" "optional"
check_tool "appinspector" "optional"
check_tool "codeql" "optional"
check_tool "cloc" "optional"
check_tool "lizard" "optional"

# Python tools
check_tool "python" "optional" || check_tool "python3" "optional"

echo "----------------------------------------"

if [ $MISSING_REQUIRED -eq 1 ]; then
    echo -e "${RED}Some required tools are missing. Agent may have limited functionality.${NC}"
else
    echo -e "${GREEN}Tool check complete. Ready for security scanning.${NC}"
fi

# Set environment variables for the agent
export GRIMBARD_OUTPUT_DIR="$OUTPUT_DIR"
export GRIMBARD_INITIALIZED=1

echo ""
echo "Grimbard agent initialized successfully."
echo "Output will be saved to: $OUTPUT_DIR"

exit 0
