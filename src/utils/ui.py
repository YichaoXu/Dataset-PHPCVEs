import os
import time
from typing import Optional, List
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from src.utils.logger import Logger

class ProgressUI:
    """Progress UI with logging capabilities."""
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        Initialize the progress UI.
        
        Args:
            total: Total number of items to process
            description: Description of the task
        """
        self.console = Console()
        self.log_buffer: List[str] = []
        
        # Create progress bar
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console
        )
        
        # Create layout
        self.layout = Layout()
        
        # Add progress to layout - Fix: use split method instead of item assignment
        self.layout.split(
            self.progress
        )
        
        # Create task
        self.task_id = self.progress.add_task(description, total=total)
        self.current_item = None
    
    def __enter__(self):
        """Start the progress UI."""
        self.progress.start()
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
    
    def update(self, advance: int = 0, current_item: Optional[str] = None, description: Optional[str] = None):
        """
        Update the progress UI.
        
        Args:
            advance: Number of steps to advance
            current_item: Current item being processed
            description: New description for the task
        """
        if current_item:
            self.current_item = current_item
        
        update_args = {}
        if advance > 0:
            update_args["advance"] = advance
        if description:
            update_args["description"] = description
        
        if self.current_item and not description:
            update_args["description"] = f"{self.progress.tasks[self.task_id].description.split(' - ')[0]} - {self.current_item}"
        
        self.progress.update(self.task_id, **update_args)
    
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