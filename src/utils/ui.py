from typing import Optional
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn, TaskProgressColumn
from src.utils.logger import Logger

class ProgressUI:
    """UI component for displaying progress with status information."""
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        Initialize the progress UI.
        
        Args:
            total: Total number of items to process
            description: Description of the progress bar
        """
        self.total = total
        self.description = description
        self.current_item = "Starting..."
        self.last_errors = []
        self.log_buffer = []
        
        # Create layout
        self.layout = Layout()
        self.layout.split(
            Layout(name="main"),
            Layout(name="footer", size=4)
        )
        
        # Create progress bar
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        )
        self.task = self.progress.add_task(description, total=total)
        
        # Set up layout components
        self.layout["main"] = self.progress
        self.layout["footer"] = self._get_status_panel()
        
        # Create console and live display
        self.console = Console()
        self.live = Live(
            self.layout, 
            console=self.console, 
            refresh_per_second=4, 
            screen=True
        )
    
    def _get_status_panel(self) -> Panel:
        """Generate status panel with current item and recent errors."""
        content = f"Current: {self.current_item}\n"
        if self.last_errors:
            content += "Recent issues:\n"
            for err in self.last_errors[-3:]:  # Show last 3 errors
                content += f"• {err}\n"
        return Panel(content, title="Status", border_style="yellow")
    
    def __enter__(self):
        """Start the live display."""
        self.live.__enter__()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End the live display."""
        self.live.__exit__(exc_type, exc_val, exc_tb)
        
        # After processing is complete, display the buffered log messages
        if self.log_buffer:
            Logger.info(f"Encountered {len(self.log_buffer)} issues during processing:")
            for i, message in enumerate(self.log_buffer[:10], 1):
                Logger.warning(f"Issue {i}: {message}")
            
            if len(self.log_buffer) > 10:
                Logger.info(f"... and {len(self.log_buffer) - 10} more issues (see log file for details)")
    
    def update(self, 
               advance: int = 1, 
               current_item: Optional[str] = None, 
               description: Optional[str] = None,
               refresh: bool = True) -> None:
        """
        Update the progress display.
        
        Args:
            advance: Number of steps to advance
            current_item: Current item being processed
            description: New description for the progress bar
            refresh: Whether to refresh the display
        """
        if current_item:
            self.current_item = current_item
        
        update_args = {"advance": advance}
        if description:
            update_args["description"] = description
        
        self.progress.update(self.task, **update_args)
        self.layout["footer"] = self._get_status_panel()
        
        if refresh:
            self.live.refresh()
    
    def log_error(self, error_msg: str, refresh: bool = True) -> None:
        """
        Log an error message.
        
        Args:
            error_msg: Error message to log
            refresh: Whether to refresh the display
        """
        self.log_buffer.append(error_msg)
        self.last_errors.append(error_msg)
        
        # Keep only the last few errors to avoid cluttering the display
        if len(self.last_errors) > 5:
            self.last_errors.pop(0)
        
        self.layout["footer"] = self._get_status_panel()
        
        if refresh:
            self.live.refresh()
    
    def write_log_to_file(self, file_path: str) -> None:
        """
        Write the log buffer to a file.
        
        Args:
            file_path: Path to the log file
        """
        with open(file_path, "w") as f:
            for message in self.log_buffer:
                f.write(f"{message}\n") 