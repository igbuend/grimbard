#!/bin/bash
# Grimbard Security Agent - Cleanup Script
# This script runs when a grimbard sub-agent completes

echo "Grimbard Security Agent cleanup..."

OUTPUT_DIR="${GRIMBARD_OUTPUT_DIR:-./grimbard-security-review}"

# Check if output directory exists
if [ -d "$OUTPUT_DIR" ]; then
    # Count findings
    SARIF_COUNT=$(find "$OUTPUT_DIR/sarif" -name "*.sarif" 2>/dev/null | wc -l)
    REPORT_COUNT=$(find "$OUTPUT_DIR/reports" -name "*.md" 2>/dev/null | wc -l)

    echo ""
    echo "Session Summary:"
    echo "----------------"
    echo "SARIF files generated: $SARIF_COUNT"
    echo "Reports generated: $REPORT_COUNT"
    echo "Output directory: $OUTPUT_DIR"

    # List critical findings if any
    if [ -f "$OUTPUT_DIR/findings/P0-critical.sarif" ]; then
        CRITICAL_COUNT=$(grep -c '"level": "error"' "$OUTPUT_DIR/findings/P0-critical.sarif" 2>/dev/null || echo "0")
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo ""
            echo "WARNING: $CRITICAL_COUNT critical findings detected!"
            echo "Review: $OUTPUT_DIR/findings/P0-critical.sarif"
        fi
    fi
fi

echo ""
echo "Grimbard agent session complete."

# Optional: Remove temporary files
# Uncomment to clean up temp files after each run
# rm -rf "$OUTPUT_DIR/logs/*.tmp" 2>/dev/null

exit 0
