"""
User interface utilities for PHP CVE Dataset Collection Tool.

This module provides UI components for displaying progress and status information.
"""

import os
from typing import Optional, List
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from src.utils.logger import Logger

console = Console()

class ProgressUI:
    """Progress UI for displaying task progress with integrated logging."""
    
    def __init__(self, total_steps, description="Processing"):
        """Initialize the progress UI."""
        self.total_steps = total_steps
        self.description = description
        self.progress = None
        self.task_id = None
        self.log_buffer: List[str] = []
    
    def __enter__(self):
        """Start the progress UI."""
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        )
        self.progress.start()
        self.task_id = self.progress.add_task(self.description, total=self.total_steps)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the progress UI."""
        self.progress.stop()
        
        # After processing is complete, display the buffered log messages
        if self.log_buffer:
            Logger.info(f"Encountered {len(self.log_buffer)} issues during processing:")
            for i, message in enumerate(self.log_buffer[:10], 1):
                Logger.warning(f"Issue {i}: {message}")
            
            if len(self.log_buffer) > 10:
                Logger.info(f"... and {len(self.log_buffer) - 10} more issues (see log file for details)")
    
    def update(self, advance, description=None):
        """Update the progress."""
        if description:
            self.progress.update(self.task_id, description=description, advance=advance)
        else:
            self.progress.update(self.task_id, advance=advance)
    
    def log(self, message):
        """Log an info message in the progress context."""
        # Add to buffer (optional)
        self.log_buffer.append(message)
        # Use Logger for actual logging
        Logger.info(message, console=self.progress.console)
    
    def log_success(self, message):
        """Log a success message in the progress context."""
        Logger.success(message, console=self.progress.console)
    
    def log_warning(self, message):
        """Log a warning message in the progress context."""
        self.log_buffer.append(message)
        Logger.warning(message, console=self.progress.console)
    
    def log_error(self, message):
        """Log an error message in the progress context."""
        self.log_buffer.append(message)
        Logger.error(message, console=self.progress.console)
    
    def write_log_to_file(self, log_file: str):
        """Write log buffer to file."""
        if not self.log_buffer:
            return
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.log_buffer))
            Logger.info(f"Errors logged to: {log_file}")
        except Exception as e:
            Logger.error(f"Failed to write log file: {str(e)}")

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
    table = Table(title=title)
    
    # Add headers
    for header in headers:
        table.add_column(header)
    
    # Add rows
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    
    console.print(table) 