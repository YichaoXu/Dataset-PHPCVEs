"""
Clean command module for PHP CVE Dataset Collection Tool.

This module provides functionality to clean up temporary files and cached data.
"""

import shutil
import time
import typer
from rich.console import Console
from rich.prompt import Confirm

from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir
from src.config import CACHE_DIR, INTER_DIR

console = Console()

def clean(
    cache: bool = typer.Option(False, help="Clean cached data"),
    intermediate: bool = typer.Option(False, help="Clean intermediate files"),
    all: bool = typer.Option(False, help="Clean all temporary files (cache and intermediate)"),
    force: bool = typer.Option(False, help="Force cleaning without confirmation"),
    verbose: bool = typer.Option(False, help="Enable verbose output")
):
    """
    Clean up temporary files and cached data.
    
    This command removes temporary files and cached data to free up disk space
    and ensure a clean state for new data collection.
    """
    # Enable verbose logging if requested
    Logger.set_verbose(verbose)
    
    # Start timing
    start_time = time.time()
    
    # Determine what to clean
    clean_cache = cache or all
    clean_intermediate = intermediate or all
    
    if not clean_cache and not clean_intermediate:
        Logger.error("No cleaning options selected. Use --cache, --intermediate, or --all.")
        raise typer.Exit(1)
    
    # Ask for confirmation if not forced
    if not force:
        message = "This will delete "
        if clean_cache and clean_intermediate:
            message += "all cached data and intermediate files"
        elif clean_cache:
            message += "all cached data"
        else:
            message += "all intermediate files"
        
        if not Confirm.ask(f"{message}. Are you sure?", default=False):
            Logger.info("Operation cancelled")
            raise typer.Exit(0)
    
    # Clean cache directory
    if clean_cache and CACHE_DIR.exists():
        Logger.info(f"Cleaning cache directory: {CACHE_DIR}")
        try:
            shutil.rmtree(CACHE_DIR)
            ensure_dir(CACHE_DIR)
            Logger.success("Cache directory cleaned")
        except Exception as e:
            Logger.error(f"Error cleaning cache directory: {str(e)}")
    
    # Clean intermediate directory
    if clean_intermediate and INTER_DIR.exists():
        Logger.info(f"Cleaning intermediate directory: {INTER_DIR}")
        try:
            shutil.rmtree(INTER_DIR)
            ensure_dir(INTER_DIR)
            Logger.success("Intermediate directory cleaned")
        except Exception as e:
            Logger.error(f"Error cleaning intermediate directory: {str(e)}")
    
    # Report timing
    elapsed_time = time.time() - start_time
    Logger.info(f"Cleaning completed in {elapsed_time:.2f} seconds") 