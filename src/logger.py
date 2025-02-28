"""
Logging utilities for PHP CVE Dataset Collection Tool.

This module provides logging functionality with different log levels and
output formats.
"""

import os
import logging
from datetime import datetime
from typing import Optional
from rich.console import Console
from .config import Config

# Configure logging
log_dir = Config.DS_INTER_PATH / ".logs"
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

class Logger:
    """Enhanced logger with rich console output and file logging."""
    
    # Rich console styles
    STYLES = {
        'info': 'blue',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red',
        'debug': 'cyan',
        'step': 'magenta',
        'path': 'bright_blue',
        'highlight': 'bold cyan'
    }
    
    # Emoji indicators
    EMOJI = {
        'info': 'ℹ️ ',
        'success': '✅',
        'warning': '⚠️ ',
        'error': '❌',
        'debug': '🔍',
        'step': '📝',
        'start': '🚀',
        'end': '🏁',
        'path': '📂',
        'download': '⬇️ ',
        'extract': '📦',
        'cache': '💾',
        'clean': '🧹'
    }
    
    # Map custom levels to standard logging levels
    LEVEL_MAP = {
        'info': 'info',
        'success': 'info',  # Map success to info level
        'warning': 'warning',
        'error': 'error',
        'debug': 'debug',
        'step': 'info'
    }
    
    def __init__(self, name: str, verbose: bool = False):
        """
        Initialize logger with name and verbosity setting.
        
        Args:
            name: Logger name
            verbose: Enable verbose logging
        """
        self.name = name
        self.verbose = verbose
        self.console = Console()
        self._logger = logging.getLogger(name)
        
    def _log(self, level: str, message: str, style: str = None, emoji: str = None,
             path: Optional[str] = None, extra_info: Optional[dict] = None):
        """
        Internal logging method.
        
        Args:
            level: Log level
            message: Main message
            style: Rich console style
            emoji: Emoji indicator
            path: Optional path to highlight
            extra_info: Additional key-value pairs to log
        """
        # Map custom level to standard level
        std_level = self.LEVEL_MAP.get(level, 'info')
        
        # File logging
        log_func = getattr(self._logger, std_level)
        log_func(message)
        
        # Console output
        style = style or self.STYLES.get(level, 'white')
        emoji = emoji or self.EMOJI.get(level, '')
        
        # Format message
        console_msg = f"{emoji} {message}"
        
        # Add path if provided
        if path:
            console_msg += f"\n   {self.EMOJI['path']} [bold {self.STYLES['path']}]Path:[/] {path}"
            
        # Add extra info if provided
        if extra_info:
            for key, value in extra_info.items():
                emoji = self.EMOJI.get(key.lower(), '📌')
                console_msg += f"\n   {emoji} [bold {style}]{key}:[/] {value}"
                
        self.console.print(f"[{style}]{console_msg}[/]")
        
    def debug(self, message: str, **kwargs):
        """Log debug message (only in verbose mode)."""
        if self.verbose:
            self._log('debug', message, **kwargs)
            
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log('info', message, **kwargs)
        
    def success(self, message: str, **kwargs):
        """Log success message."""
        self._log('success', message, **kwargs)
        
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log('warning', message, **kwargs)
        
    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log('error', message, **kwargs)
        
    def step(self, message: str, **kwargs):
        """Log step/progress message."""
        self._log('info', message, style='step', emoji=self.EMOJI['step'], **kwargs)
        
    def start_process(self, message: str):
        """Log process start."""
        self._log('info', f"=== {message} ===", style='highlight', emoji=self.EMOJI['start'])
        
    def operation(self, op_type: str, message: str, path: Optional[str] = None, **extra):
        """
        Log an operation with optional path and extra information.
        
        Args:
            op_type: Operation type (e.g., 'download', 'extract', 'cache')
            message: Operation message
            path: Optional path related to operation
            **extra: Additional key-value pairs to log
        """
        style = self.STYLES.get(op_type, 'cyan')
        emoji = self.EMOJI.get(op_type, '📌')
        self._log('info', message, style=style, emoji=emoji, path=path, extra_info=extra)

# Create default logger instance
logger = Logger('php_cve_tool') 