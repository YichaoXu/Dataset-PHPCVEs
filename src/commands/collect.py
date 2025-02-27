import os
import typer
from pathlib import Path
from typing import Optional
from utils.logger import Logger
from utils.github import GitHubAPI
from core.processor import CVEProcessor
from core.extractor import CVEExtractor
from core.downloader import CVEDownloader
from utils.file_utils import ensure_dir, copy_file
from utils.error_handler import ErrorHandler
from config import config

def collect(
    output_dir: str = typer.Argument(..., help="📂 Output directory path (required)"),
    github_token: Optional[str] = typer.Option(None, "--token", help="🔑 GitHub API Token"),
    do_use_cache: bool = typer.Option(True, "--no-cache", help="🔄 Disable using cached dataset"),
):
    """
    Collect PHP-related CVE dataset with commit information.
    
    This command downloads the latest CVE data, filters for PHP-related vulnerabilities,
    extracts GitHub commit information, and saves the results to a CSV file.
    """
    # Set up directories
    output_dir = Path(output_dir)
    ensure_dir(output_dir)
    ensure_dir(config.inter_dir)
    
    # Define paths
    dataset_path: Path = output_dir / "dataset.csv"
    cache_path: Path = config.cache_dir / "dataset.csv"
    
    # Check cache
    if do_use_cache and cache_path.exists():
        Logger.info("Using cached dataset")
        copy_file(cache_path, dataset_path)
        return

    # Initialize components
    github_api = GitHubAPI(github_token)
    downloader = CVEDownloader(config.inter_dir, do_use_cache)
    extractor = CVEExtractor(config.inter_dir, do_use_cache)
    processor = CVEProcessor(github_api)

    try:
        # Step 1: Get CVE data (download and extract)
        if not extractor.cve_data_exists() or not do_use_cache:
            # Download and extract CVE data
            if not downloader.download_cve_data():
                raise typer.Exit(code=1)
            
            if not extractor.extract_cve_data():
                raise typer.Exit(code=1)
        else:
            Logger.info("Using existing CVE data directory")

        # Step 2: Process CVE files
        records = processor.process_cve_files(extractor.get_cve_dir())
        
        # Step 3: Save results
        if not records:
            Logger.warning("No PHP-related CVEs found")
            raise typer.Exit(code=1)
        
        # Save dataset
        processor.save_dataset(records, dataset_path, cache_path)
        Logger.success(f"Dataset saved to: {dataset_path}")
        
        # Print statistics
        processor.print_cwe_distribution(records)

    except Exception as e:
        import traceback
        Logger.error(f"Collection failed: {str(e)}")
        Logger.error(traceback.format_exc())
        raise typer.Exit(code=1) 