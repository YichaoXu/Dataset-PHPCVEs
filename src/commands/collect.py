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
from src.config import CACHE_DIR, INTER_DIR

console = Console()

# Command-specific directories
COLLECT_INTER_DIR = INTER_DIR / "collect"
DEFAULT_OUTPUT_DIR = Path("output/collect")

def collect(
    output_dir: Path = typer.Argument(DEFAULT_OUTPUT_DIR, help="Directory to store collected data"),
    token: Optional[str] = typer.Option(None, help="GitHub API token"),
    year: Optional[int] = typer.Option(None, help="Specific year to collect (default: all years)"),
    force: bool = typer.Option(False, help="Force reprocessing of cached data"),
    verbose: bool = typer.Option(False, help="Enable verbose output")
):
    """
    This command is part of a PHP CVE Dataset Collection Tool that helps gather and process vulnerability data. It takes an output directory path and optional parameters like a GitHub token, specific year, force flag, and verbose mode. 
    The command downloads CVE (Common Vulnerabilities and Exposures) data from various sources, specifically focusing on PHP-related security issues. 
    It processes this data by first downloading and extracting CVE information, then applies filters to identify PHP vulnerabilities. 
    For each vulnerability, it extracts associated GitHub commit information to understand the code changes that fixed the issue. 
    The tool also analyzes project README files to classify the type of PHP project affected. All this collected and processed data is then saved in both CSV and JSON formats, organized by year in the specified output directory. 
    The command uses caching to improve performance on subsequent runs, unless forced to reprocess with the force flag.
    """
    # Enable verbose logging if requested
    Logger.set_verbose(verbose)
    
    # Start timing
    start_time = time.time()
    
    # Create output directory
    ensure_dir(output_dir)
    
    # Create intermediate directory for processing data
    ensure_dir(COLLECT_INTER_DIR)
    
    # Initialize GitHub API client
    github_api = GitHubAPI(token=token)
    
    # Initialize processor
    processor = CVEProcessor(
        github_api=github_api,
        cache_dir=CACHE_DIR,
        inter_dir=COLLECT_INTER_DIR,
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