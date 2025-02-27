import os
import typer
from pathlib import Path
from typing import Optional
from src.utils.logger import Logger
from src.utils.github import GitHubAPI
from src.core.processor import CVEProcessor
from src.core.extractor import CVEExtractor
from src.core.downloader import CVEDownloader
from src.utils.file_utils import ensure_dir, copy_file
from src.config import config

def collect(
    output_dir: str = typer.Argument(..., help="📂 Output directory path (required)"),
    github_token: Optional[str] = typer.Option(None, "--token", help="🔑 GitHub API Token"),
    do_use_cache: bool = typer.Option(True, "--no-cache", help="🔄 Disable using cached dataset"),
    use_processed_cache: bool = typer.Option(True, "--no-processed-cache", help="🔄 Disable using processed CVE cache"),
):
    """
    Collect PHP-related CVE dataset with commit information.
    
    This command downloads the latest CVE data, filters for PHP-related vulnerabilities,
    extracts GitHub commit information, and saves the results to a CSV file.
    """
    try:
        # Set up directories
        output_dir = Path(output_dir)
        ensure_dir(output_dir)
        ensure_dir(config.inter_dir)
        
        # Define command-specific cache directories
        collect_cache_dir = config.inter_dir / "collect"
        ensure_dir(collect_cache_dir)
        
        cve_zip_path = collect_cache_dir / "cve_data.zip"
        cve_dir = collect_cache_dir / "cves"
        cve_processed_dir = collect_cache_dir / "processed"
        dataset_cache_path = collect_cache_dir / "dataset.csv"
        
        # Define paths
        dataset_path: Path = output_dir / "dataset.csv"
        
        # Check cache
        if do_use_cache and dataset_cache_path.exists():
            Logger.info("Using cached dataset")
            copy_file(dataset_cache_path, dataset_path)
            return

        # Initialize components
        github_api = GitHubAPI(github_token)
        downloader = CVEDownloader(collect_cache_dir, cve_zip_path, do_use_cache)
        extractor = CVEExtractor(collect_cache_dir, cve_dir, cve_zip_path, do_use_cache)
        processor = CVEProcessor(github_api, cve_processed_dir, use_processed_cache)

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
        processor.save_dataset(records, dataset_path, dataset_cache_path)
        Logger.success(f"Dataset saved to: {dataset_path}")
        
        # Print statistics
        processor.print_cwe_distribution(records)

    except Exception as e:
        import traceback
        Logger.error(f"Collection failed: {str(e)}")
        Logger.error(traceback.format_exc())
        raise typer.Exit(code=1) 