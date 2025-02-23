import os
import csv
import requests
import argparse
import zipfile
import shutil
from collections import defaultdict

def normalize_cwe(cwe_string):
    """Standardize CWE-ID (supporting both prefixed and non-prefixed forms, e.g., 502 → CWE-502)"""
    if not cwe_string:
        return set()  # Return an empty set if no CWE is provided, meaning download all
    return {f"CWE-{cwe}" if not cwe.startswith("CWE-") else cwe for cwe in cwe_string.split(",")}

def download_commit_archive(repo_url, commit_hash, save_path, headers):
    """Download and extract the specified commit archive from GitHub, placing contents directly in save_path"""
    repo_path = repo_url.replace("https://github.com/", "").strip()
    archive_url = f"https://github.com/{repo_path}/archive/{commit_hash}.zip"
    if os.path.exists(save_path): 
        shutil.rmtree(save_path)
    os.makedirs(save_path, exist_ok=False)
    print(f"Downloading {repo_path}/{commit_hash} to {save_path}")
    response = requests.get(archive_url, headers=headers, stream=True)
    if response.status_code == 200:
        zip_path = f"{save_path}.zip"
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Extract the downloaded zip file to a temporary directory
        temp_extract_path = f"{save_path}_temp"
        os.makedirs(temp_extract_path, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_extract_path)

        # Move extracted contents to save_path, preserving structure
        extracted_root = os.path.join(temp_extract_path, os.listdir(temp_extract_path)[0])  # Extracted folder
        for item in os.listdir(extracted_root):
            src_path = os.path.join(extracted_root, item)
            dest_path = os.path.join(save_path, item)
            if os.path.isdir(src_path):
                shutil.move(src_path, dest_path)
            else:
                shutil.move(src_path, save_path)

        # Cleanup
        shutil.rmtree(temp_extract_path)
        os.remove(zip_path)
        print(f"Extracted files successfully to {save_path}")
    else:
        print(f"❌ Failed to download {repo_url} commit {commit_hash}, Status Code: {response.status_code}")

def process_csv(csv_file, target_cwes, download_dir, github_token):
    """Read the CSV file and download previous commit archives matching the target CWE types, organizing them by CWE."""
    headers = {"Authorization": f"token {github_token}"} if github_token else {}
    cwe_folders = defaultdict(list)

    with open(csv_file, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header row

        for row in reader:
            if len(row) < 5: continue  # Ensure row data is complete

            cve_id, cwe_type, repo_url, _, prev_commit = row
            cwe_type, _, _ = cwe_type.strip().partition(":")

            # If `--cwes` is empty, download all; otherwise, match specific CWE types
            if target_cwes and cwe_type not in target_cwes: continue
            # Organize downloads by CWE type
            cwe_folder = os.path.join(download_dir, cwe_type)
            os.makedirs(cwe_folder, exist_ok=True)
            cwe_folders[cwe_type].append(cve_id)

            # Create CVE-specific folder
            cve_folder = os.path.join(cwe_folder, cve_id)
            os.makedirs(cve_folder, exist_ok=True)

            # Define the target ZIP file path
            repo_uname = repo_url.partition("github.com/")[2].replace("_", "").replace("/", "_")
            storage_path = os.path.join(cve_folder, f"{repo_uname}_{prev_commit[:6]}")
            # Download the previous commit archive
            download_commit_archive(repo_url, prev_commit, storage_path, headers)
    print(f"✅ Downloaded {len(cwe_folders)} CWE types.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download GitHub commit archives for specified CWE types")
    parser.add_argument("--token", type=str, default="", help="GitHub API token (optional)")
    parser.add_argument("--cwes", type=str, default="", help="Specify CWE types to download (use , to separate, e.g., CWE-502,79)")
    parser.add_argument("csv", type=str, default="repo_list.csv", help="Path to the CSV file")
    parser.add_argument("output", type=str, default="CVE_Archives", help="Download directory")

    args = parser.parse_args()
    
    target_cwes = normalize_cwe(args.cwes)  # Process CWE-ID normalization
    os.makedirs(args.output, exist_ok=True)  # Ensure the output directory exists
    process_csv(args.csv, target_cwes, args.output, args.token)
