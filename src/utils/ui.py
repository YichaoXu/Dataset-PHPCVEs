"""
User interface utilities for PHP CVE Dataset Collection Tool.

This module provides UI components for displaying progress and status information.
"""

import os
import time
from typing import Optional, List, Any
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from src.utils.logger import Logger

console = Console()

class ProgressUI:
    """Progress bar UI component."""
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        Initialize progress UI.
        
        Args:
            total: Total number of items to process
            description: Description of the task
        """
        self.total = total
        self.description = description
        self.progress = None
        self.task_id = None
        self.console = Console()
        self.log_buffer: List[str] = []
        
        # Create layout
        self.layout = Layout()
        
        # Add progress to layout - Fix: use split method instead of item assignment
        self.layout.split(
            self.progress
        )
        
        # Create task
        self.task_id = self.progress.add_task(description, total=total)
        self.current_item = None
    
    def __enter__(self) -> 'ProgressUI':
        """Enter context manager."""
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeRemainingColumn()
        )
        self.progress.start()
        self.task_id = self.progress.add_task(self.description, total=self.total)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        if self.progress:
            self.progress.stop()
        
        # After processing is complete, display the buffered log messages
        if self.log_buffer:
            Logger.info(f"Encountered {len(self.log_buffer)} issues during processing:")
            for i, message in enumerate(self.log_buffer[:10], 1):
                Logger.warning(f"Issue {i}: {message}")
            
            if len(self.log_buffer) > 10:
                Logger.info(f"... and {len(self.log_buffer) - 10} more issues (see log file for details)")
    
    def update(self, advance: int = 1, current_item: Optional[str] = None):
        """
        Update progress.
        
        Args:
            advance: Number of steps to advance
            current_item: Current item being processed (for display)
        """
        if self.progress and self.task_id is not None:
            description = self.description
            if current_item:
                description = f"{self.description}: {current_item}"
            
            self.progress.update(self.task_id, advance=advance, description=description)
    
    def log_error(self, message: str, show_in_progress: bool = False) -> None:
        """
        Log an error message.
        
        Args:
            message: Error message
            show_in_progress: Whether to show the error in the progress bar
        """
        # Add to log buffer
        self.log_buffer.append(message)
        
        # Only show in progress bar if explicitly requested
        if show_in_progress:
            self.progress.print(f"❌ {message}")
    
    def write_log_to_file(self, log_file: str):
        """
        Write log buffer to file.
        
        Args:
            log_file: Path to log file
        """
        if not self.log_buffer:
            return
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.log_buffer))
            self.console.print(f"[yellow]Errors logged to: {log_file}[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Failed to write log file: {str(e)}[/red]")

def confirm_action(message: str, default: bool = False) -> bool:
    """
    Ask for user confirmation.
    
    Args:
        message: Confirmation message
        default: Default response if user just presses Enter
        
    Returns:
        True if confirmed, False otherwise
    """
    default_str = "Y/n" if default else "y/N"
    response = input(f"{message} [{default_str}]: ").strip().lower()
    
    if not response:
        return default
    
    return response.startswith('y')

def print_table(headers: list, rows: list, title: Optional[str] = None):
    """
    Print a formatted table.
    
    Args:
        headers: Table headers
        rows: Table rows
        title: Optional table title
    """
    from rich.table import Table
    
    table = Table(title=title)
    
    # Add headers
    for header in headers:
        table.add_column(header)
    
    # Add rows
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    
    console.print(table) 