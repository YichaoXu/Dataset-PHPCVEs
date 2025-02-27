import os
import csv
import time
from pathlib import Path
import typer
from src.utils.logger import Logger
from src.core.validator import DataValidator
from src.core.downloader import CodeDownloader
from src.models.metadata import MetadataGenerator
from src.commands.collect import collect
from src.config import config

def download(
    output_dir: str = typer.Argument(..., help="📂 Download output directory path (required)"),
    dataset_path: str = typer.Option(None, help="📊 Dataset CSV file path"),
    cwes: str = typer.Option("", help="🎯 CWE ID list (comma-separated, empty for all)"),
    project_types: str = typer.Option("", help="🏷️ Project types to include (comma-separated, empty for all)"),
    github_token: str = typer.Option(None, "--token", help="🔑 GitHub API Token"),
    enforce: bool = typer.Option(False, help="🔄 Force download even if directory exists")
):
    """
    Download vulnerable PHP code from GitHub repositories.
    
    This command downloads the vulnerable code versions (previous commits) from GitHub
    repositories identified in the dataset. The code is organized by CWE type and CVE ID.
    
    """
    # Set up output directory
    output_dir = Path(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # Define command-specific cache directories
    download_cache_dir = config.inter_dir / "download"
    ensure_dir(download_cache_dir)
    
    # Use dataset path if provided, otherwise look in output directory
    if dataset_path:
        dataset_path = Path(dataset_path)
    else:
        dataset_path = output_dir / "dataset.csv"

    if not dataset_path.exists():
        Logger.warning("Dataset not found, collecting data first...")
        collect(str(output_dir), github_token=github_token)
        dataset_path = output_dir / "dataset.csv"

    if not DataValidator.validate_dataset(dataset_path):
        raise typer.Exit(code=1)

    target_cwes = {f"CWE-{cwe}" if not cwe.startswith("CWE-") else cwe 
                   for cwe in cwes.split(",")} if cwes else set()
    target_types = {pt.strip() for pt in project_types.split(",")} if project_types else set()
    
    try:
        with open(dataset_path, 'r') as f:
            reader = csv.DictReader(f)
            total = sum(1 for _ in reader)
            f.seek(0)
            next(reader)

            with typer.progressbar(reader, length=total, 
                                 label="Downloading repositories") as progress:
                for row in progress:
                    # Check if CWE and project type match filters
                    if target_cwes and row['cwe_type'] not in target_cwes:
                        continue
                    if target_types and row['project_type'] not in target_types:
                        continue

                    # Create CWE and CVE specific folders
                    cwe_dir = output_dir / row['cwe_type']
                    cve_dir = cwe_dir / row['cve_id']
                    
                    # Skip if already downloaded and enforce is False
                    if not enforce and MetadataGenerator.is_download_complete(cve_dir):
                        Logger.info(f"Skipping {row['cve_id']}: already downloaded")
                        continue
                        
                    os.makedirs(cve_dir, exist_ok=True)

                    # Download previous commit only
                    repo_name = row['repository'].replace("https://github.com/", "").replace("/", "_")
                    save_path = cve_dir / f"{repo_name}_{row['previous_commit'][:6]}"
                    
                    if CodeDownloader.download_commit(row['repository'], row['previous_commit'], str(save_path)):
                        # Generate metadata after successful download
                        MetadataGenerator.generate_metadata(row, cve_dir)
                        time.sleep(1)  # Rate limiting
                    else:
                        Logger.error(f"Failed to download {row['cve_id']}")

        Logger.success("Download completed")

    except Exception as e:
        Logger.error(f"Download failed: {e}")
        raise typer.Exit(code=1) 