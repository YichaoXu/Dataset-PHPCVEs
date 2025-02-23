#!/bin/bash
set -e  # Exit on error

# Default input and output directories
INPUT_DIR="/input"
OUTPUT_DIR="/output"

# Allow user to override paths via arguments
if [ ! -z "$1" ]; then
    INPUT_DIR="$1"
fi
if [ ! -z "$2" ]; then
    OUTPUT_DIR="$2"
fi

echo "🚀 Starting container setup with:"
echo "   📂 INPUT_DIR:  $INPUT_DIR"
echo "   📂 OUTPUT_DIR: $OUTPUT_DIR"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check and download CVE dataset if missing
if [ ! -f "$OUTPUT_DIR/dataset.csv" ]; then
    echo "📂 dataset.csv not found in output. Checking for data..."
    if [ ! -f "$INPUT_DIR/dataset.csv" ]; then
        echo "⬇️  Downloading CVE dataset..."
        wget -O cve_data.zip.zip "https://github.com/CVEProject/cvelistV5/releases/download/cve_2025-02-14_1700Z/2025-02-14_all_CVEs_at_midnight.zip.zip" \
        && unzip cve_data.zip.zip && rm cve_data.zip.zip \
        && unzip cves.zip && rm cves.zip \
        && python "$INPUT_DIR/extracter.py" --filter-unknown --output-csv "$INPUT_DIR/dataset.csv" cves && rm -rdf cves

        echo "🔍 Extracting CVE records..."
        python "$INPUT_DIR/extracter.py" --filter-unknown --output-csv "$INPUT_DIR/dataset.csv" cves
        rm -rdf cves
    fi

    # Copy dataset.csv to output
    cp "$INPUT_DIR/dataset.csv" "$OUTPUT_DIR/dataset.csv"
    echo "✅ dataset.csv copied to output"
else
    echo "✅ dataset.csv already exists in output, skipping download."
fi

# Generate statistics if missing
if [ ! -f "$OUTPUT_DIR/statistic.csv" ]; then
    echo "📂 statistic.csv not found in output. Checking for data..."
    if [ ! -f "$INPUT_DIR/statistic.csv" ]; then
        echo "📊 Generating statistics..."
        python "$INPUT_DIR/counter.py" "$OUTPUT_DIR/dataset.csv" --output-csv "$INPUT_DIR/statistic.csv"
    fi 
    # Copy statistic.csv to output
    cp "$INPUT_DIR/statistic.csv" "$OUTPUT_DIR/statistic.csv"
    echo "✅ statistic.csv copied to output"
else
    echo "✅ statistic.csv already exists in output, skipping generation."
fi

# Execute the main script
echo "🚀 Running download.py..."
exec python "$INPUT_DIR/download.py" --cwes "79,89,434,94,77,78" "$OUTPUT_DIR/dataset.csv" "$OUTPUT_DIR"
echo "✅ download.py completed successfully."