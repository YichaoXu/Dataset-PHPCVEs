"""
Logging utilities for PHP CVE Dataset Collection Tool.

This module provides logging functionality with different log levels and
output formats.
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

# Configure logging
log_dir = Path(".logs")
os.makedirs(log_dir, exist_ok=True)

# Create logger
logger = logging.getLogger("php_cve_tool")
logger.setLevel(logging.DEBUG)

# Create file handler
log_file = log_dir / f"app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)

# Rich console for pretty output
console = Console()

class Logger:
    """Static logger class for application-wide logging."""
    
    @staticmethod
    def debug(message: str):
        """
        Log a debug message (file only).
        
        Args:
            message: Debug message
        """
        logger.debug(message)
    
    @staticmethod
    def info(message: str):
        """
        Log an info message.
        
        Args:
            message: Info message
        """
        logger.info(message)
        console.print(f"[blue]INFO:[/blue] {message}")
    
    @staticmethod
    def warning(message: str):
        """
        Log a warning message.
        
        Args:
            message: Warning message
        """
        logger.warning(message)
        console.print(f"[yellow]WARNING:[/yellow] {message}")
    
    @staticmethod
    def error(message: str):
        """
        Log an error message.
        
        Args:
            message: Error message
        """
        logger.error(message)
        console.print(f"[red]ERROR:[/red] {message}")
    
    @staticmethod
    def success(message: str):
        """
        Log a success message.
        
        Args:
            message: Success message
        """
        logger.info(f"SUCCESS: {message}")
        console.print(f"[green]SUCCESS:[/green] {message}")
    
    @staticmethod
    def set_verbose(verbose: bool):
        """
        Set verbose logging mode.
        
        Args:
            verbose: Whether to enable verbose logging
        """
        if verbose:
            console.print("[yellow]Verbose logging enabled[/yellow]")
            # Add console handler for debug messages
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler) 