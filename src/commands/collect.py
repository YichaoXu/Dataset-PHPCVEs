import os
import json
import shutil
import requests
import zipfile
import csv
from pathlib import Path
from typing import Optional
from src.utils.logger import Logger
from src.utils.github import GitHubAPI
from src.core.processor import CVEProcessor
from src.config import config

def collect(
    output_dir: str = None,
    github_token: Optional[str] = None,
    do_use_cache: bool = True,
):
    """Collect PHP-related CVE dataset with commit information"""
    output_dir = Path(output_dir or os.path.dirname(os.path.abspath(__file__)))
    dataset_path: Path = output_dir / "dataset.csv"
    cache_path: Path = config.cache_dir / "dataset.csv"

    # Check cache
    if do_use_cache and cache_path.exists():
        Logger.info("Using cached dataset")
        shutil.copy2(cache_path, dataset_path)
        return

    github_api = GitHubAPI(github_token)
    cve_processor = CVEProcessor(github_api)

    try:
        # Download CVE data
        Logger.info("Downloading CVE dataset...")
        response = requests.get(config.cve_url)
        zip_path: Path = output_dir / "cve_data.zip"
        
        with open(zip_path, 'wb') as f:
            f.write(response.content)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)

        # Process CVE files
        cve_dir = output_dir / "cves"
        records = []
        
        json_files = list(cve_dir.rglob("*.json"))
        with typer.progressbar(json_files, label="Processing CVEs") as progress:
            for json_file in progress:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if record := cve_processor.process_cve(data):
                        records.append(record)

        # Save results
        if records:
            fieldnames = ['cve_id', 'cwe_type', 'repository', 'current_commit', 'previous_commit', 'project_type']
            with open(dataset_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(records)

            # Cache the dataset
            os.makedirs(config.cache_dir, exist_ok=True)
            shutil.copy2(dataset_path, cache_path)
            
            Logger.success(f"Found {len(records)} PHP-related CVEs")
        else:
            Logger.warning("No PHP-related CVEs found")

        # Cleanup
        shutil.rmtree(cve_dir, ignore_errors=True)
        zip_path.unlink(missing_ok=True)

    except Exception as e:
        Logger.error(f"Collection failed: {e}")
        raise typer.Exit(code=1) 