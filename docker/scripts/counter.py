import csv
import argparse
from collections import Counter

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Count occurrences of CWE types from a CSV file and sort them.")
    parser.add_argument("input_csv", type=str, help="Input CSV file containing CVE data")
    parser.add_argument("--output-csv", type=str, default="statistics.csv",
                        help="Output CSV file for CWE statistics (default: cwe_statistics.csv)")
    return parser.parse_args()

def count_cwe_occurrences(input_csv):
    """Reads the input CSV and counts occurrences of each CWE type."""
    cwe_counter = Counter()

    try:
        with open(input_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row

            for row in reader:
                if len(row) < 2:
                    continue  # Skip malformed rows
                
                cwe_info = row[1].strip()  # Full CWE description (e.g., "CWE-79: Cross-site Scripting (XSS)")
                cwe_counter[cwe_info] += 1

    except Exception as e:
        print(f"⚠️ Error processing file {input_csv}: {e}")
    
    return cwe_counter

def save_cwe_statistics(cwe_counts, output_csv):
    """Saves the CWE statistics to a CSV file, sorted by count in descending order."""
    sorted_cwe_counts = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CWE Description", "Count"])
        for cwe_description, count in sorted_cwe_counts:
            writer.writerow([cwe_description, count])

def main():
    """Main function to process CWE statistics."""
    args = parse_args()
    
    # Count occurrences of each CWE type
    cwe_counts = count_cwe_occurrences(args.input_csv)

    # Save sorted results
    if cwe_counts:
        save_cwe_statistics(cwe_counts, args.output_csv)
        print(f"✅ CWE statistics saved to {args.output_csv}.")
    else:
        print("❌ No CWE data found in the input file.")

if __name__ == "__main__":
    main()