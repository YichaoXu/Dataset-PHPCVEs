import typer
from typing import Any

class Logger:
    """Utility for consistent logging throughout the application."""
    
    @staticmethod
    def info(message: Any) -> None:
        """Log an informational message."""
        typer.echo(f"ℹ️ {message}")
    
    @staticmethod
    def success(message: Any) -> None:
        """Log a success message."""
        typer.echo(f"✅ {message}")
    
    @staticmethod
    def warning(message: Any) -> None:
        """Log a warning message."""
        typer.echo(f"⚠️ {message}")
    
    @staticmethod
    def error(message: Any) -> None:
        """Log an error message."""
        typer.echo(f"❌ {message}")
    
    @staticmethod
    def debug(message: str) -> None:
        """Log debug message to file only, not to console."""
        if Logger.logger:
            Logger.logger.debug(message)
        
        # Also add to log file buffer if enabled
        if Logger.log_to_file:
            with open(Logger.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[DEBUG] {message}\n") 