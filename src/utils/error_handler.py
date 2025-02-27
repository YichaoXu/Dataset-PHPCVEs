"""
Error handling utilities for PHP CVE Dataset Collection Tool.

This module provides error handling functionality, including retry mechanisms
and standardized error reporting.
"""

import time
import traceback
from typing import Callable, Any, Optional, TypeVar, List
from functools import wraps
from src.utils.logger import Logger

T = TypeVar('T')

class ErrorHandler:
    """Error handling utilities for the application."""
    
    @staticmethod
    def with_retry(
        func: Callable[..., T], 
        *args, 
        max_retries: int = 3, 
        retry_delay: int = 2,
        backoff_factor: float = 1.5,
        error_msg: str = "Operation failed",
        **kwargs
    ) -> Optional[T]:
        """
        Execute a function with retry logic.
        
        Args:
            func: Function to execute
            *args: Positional arguments for the function
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries in seconds
            backoff_factor: Factor to increase delay with each retry
            error_msg: Error message prefix for logging
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result or None if all attempts fail
        """
        attempt = 0
        last_error = None
        
        while attempt < max_retries:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                attempt += 1
                last_error = e
                
                if attempt < max_retries:
                    delay = retry_delay * (backoff_factor ** (attempt - 1))
                    Logger.warning(f"{error_msg}: {str(e)}. Retrying in {delay:.1f}s ({attempt}/{max_retries})")
                    time.sleep(delay)
                else:
                    # Log the final error
                    Logger.error(f"{error_msg}: {str(e)}. All {max_retries} attempts failed.")
        
        return None
    
    @staticmethod
    def log_exceptions(func: Callable) -> Callable:
        """
        Decorator to log exceptions from a function.
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                Logger.error(f"Error in {func.__name__}: {str(e)}")
                Logger.debug(traceback.format_exc())
                raise
        return wrapper
    
    @staticmethod
    def collect_errors(errors: List[Exception]) -> str:
        """
        Collect error messages into a single string.
        
        Args:
            errors: List of exceptions
            
        Returns:
            Combined error message
        """
        if not errors:
            return "No errors"
        
        if len(errors) == 1:
            return f"Error: {str(errors[0])}"
        
        error_messages = [f"- {str(e)}" for e in errors]
        return f"{len(errors)} errors occurred:\n" + "\n".join(error_messages)

    @staticmethod
    def try_multiple_encodings(file_path, encodings=None):
        """Try to open a file with multiple encodings."""
        if encodings is None:
            encodings = ['utf-8', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read(), encoding
            except UnicodeDecodeError:
                continue
        
        raise UnicodeError(f"Could not decode file {file_path} with any of the encodings: {encodings}")
    
    @staticmethod
    def safe_execute(func: Callable[..., T], *args, default_value: Any = None, **kwargs) -> T:
        """Execute a function safely, returning a default value on error."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            Logger.warning(f"Error executing {func.__name__}: {str(e)}")
            return default_value 