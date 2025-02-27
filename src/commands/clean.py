"""
Clean command module for PHP CVE Dataset Collection Tool.

This module provides functionality to clean up temporary files and directories.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console

from src.utils.logger import Logger
from src.utils.ui import confirm_action
from src.config import config

console = Console()

def clean(
    cache: bool = typer.Option(False, help="Clean cache files"),
    downloads: bool = typer.Option(False, help="Clean downloaded files"),
    all: bool = typer.Option(False, help="Clean all files"),
    force: bool = typer.Option(False, help="Force cleaning without confirmation")
):
    """
    Clean up temporary files and directories.
    
    This command removes temporary files and directories created by the tool,
    such as cache files and downloaded code.
    """
    # Determine what to clean
    clean_cache = cache or all
    clean_downloads = downloads or all
    
    if not clean_cache and not clean_downloads:
        Logger.warning("No cleaning options specified. Use --cache, --downloads, or --all.")
        return
    
    # Get directories to clean
    dirs_to_clean = []
    
    if clean_cache:
        cache_dir = Path(".inter")
        if cache_dir.exists():
            dirs_to_clean.append(cache_dir)
    
    if clean_downloads:
        download_dirs = [
            Path("downloads"),
            Path("output")
        ]
        dirs_to_clean.extend([d for d in download_dirs if d.exists()])
    
    if not dirs_to_clean:
        Logger.info("No directories to clean.")
        return
    
    # Confirm cleaning
    if not force:
        dirs_str = "\n- ".join([""] + [str(d) for d in dirs_to_clean])
        if not confirm_action(f"This will delete the following directories:{dirs_str}\nAre you sure?", default=False):
            Logger.info("Cleaning cancelled.")
            return
    
    # Clean directories
    for directory in dirs_to_clean:
        try:
            shutil.rmtree(directory)
            Logger.success(f"Removed {directory}")
        except Exception as e:
            Logger.error(f"Failed to remove {directory}: {str(e)}")
    
    Logger.success("Cleaning completed.") 