"""
Collect command module for PHP CVE Dataset Collection Tool.

This module provides functionality to collect PHP-related CVEs from various sources,
filter them, and extract GitHub commit information.
"""

import time
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from src.core.processor import CVEProcessor
from src.utils.github import GitHubAPI
from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir
from src.config import config

console = Console()
def collect(
    output_dir: Path = typer.Argument(Path("output"), help="Directory to store collected data"),
    token: Optional[str] = typer.Option(None, help="GitHub API token"),
    year: Optional[int] = typer.Option(None, help="Specific year to collect (default: all years)"),
    force: bool = typer.Option(False, help="Force reprocessing of cached data"),
    verbose: bool = typer.Option(False, help="Enable verbose output")
):
    """
    Collect PHP-related CVEs from various sources.
    
    This command downloads CVE data, filters for PHP-related vulnerabilities, and extracts
    GitHub commit information to create a structured dataset.
    """
    # Enable verbose logging if requested
    Logger.set_verbose(verbose)
    
    # Start timing
    start_time = time.time()

    # Command-specific directories
    inter_collect_dir = config.inter_dir / "collect"
    
    # Create output directory
    ensure_dir(output_dir)
    
    # Create intermediate directory for processing data
    ensure_dir(inter_collect_dir)
    
    # Initialize GitHub API client
    github_api = GitHubAPI(token=token)
    
    # Initialize processor
    processor = CVEProcessor(
        github_api=github_api,
        cache_dir=config.cache_dir,
        inter_dir=inter_collect_dir,
        use_cache=not force
    )
    
    # Determine years to process
    current_year = time.localtime().tm_year
    if year:
        years_to_process = [year]
    else:
        years_to_process = list(range(2002, current_year + 1))
    
    Logger.info(f"Collecting PHP-related CVEs for years: {years_to_process[0]}-{years_to_process[-1]}")
    
    # Process each year
    total_records = 0
    for year in years_to_process:
        year_dir = output_dir / str(year)
        ensure_dir(year_dir)
        
        # Process CVEs for this year
        Logger.info(f"Processing year {year}...")
        records = processor.process_year(year, force=force)
        
        if records:
            total_records += len(records)
            
            # Save results
            csv_file = year_dir / f"php_cves_{year}.csv"
            json_file = year_dir / f"php_cves_{year}.json"
            
            processor.save_records(records, csv_file=csv_file, json_file=json_file)
            Logger.success(f"Saved {len(records)} records for year {year}")
    
    # Generate combined dataset
    if total_records > 0:
        combined_csv = output_dir / "collected_data.csv"
        combined_json = output_dir / "collected_data.json"
        
        processor.combine_yearly_data(output_dir, combined_csv, combined_json)
        Logger.success(f"Combined dataset saved to {combined_csv} and {combined_json}")
    
    # Report timing
    elapsed_time = time.time() - start_time
    Logger.info(f"Collection completed in {elapsed_time:.2f} seconds")
    Logger.success(f"Total PHP-related CVEs collected: {total_records}")
    
    return total_records 