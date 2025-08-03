"""Logging configuration and utilities."""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from .config import Config, LoggingConfig


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output."""
    
    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        """Format log record with colors."""
        if hasattr(record, 'color_output') and record.color_output:
            # Add color to level name
            level_color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{level_color}{record.levelname}{self.RESET}"
        
        return super().format(record)


class ContextFilter(logging.Filter):
    """Filter to add context information to log records."""
    
    def __init__(self, color_output: bool = True):
        super().__init__()
        self.color_output = color_output
    
    def filter(self, record):
        """Add context information to the record."""
        record.color_output = self.color_output
        return True


class LoggingManager:
    """Centralized logging management."""
    
    def __init__(self, config: Optional[LoggingConfig] = None):
        """Initialize logging manager.
        
        Args:
            config: Logging configuration, uses default if None
        """
        self.config = config or LoggingConfig()
        self._loggers_configured = set()
        self._console = Console()
    
    def setup_logging(
        self, 
        logger_name: str = "rhoai_security_manifest",
        color_output: bool = True,
        quiet: bool = False
    ) -> logging.Logger:
        """Set up logging for the application.
        
        Args:
            logger_name: Name of the logger to configure
            color_output: Whether to enable colored output
            quiet: Whether to suppress console output
            
        Returns:
            Configured logger instance
        """
        if logger_name in self._loggers_configured:
            return logging.getLogger(logger_name)
        
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, self.config.level))
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Console handler
        if not quiet:
            self._setup_console_handler(logger, color_output)
        
        # File handler
        if self.config.file_enabled:
            self._setup_file_handler(logger)
        
        # Prevent duplicate logs from parent loggers
        logger.propagate = False
        
        self._loggers_configured.add(logger_name)
        return logger
    
    def _setup_console_handler(self, logger: logging.Logger, color_output: bool) -> None:
        """Set up console logging handler.
        
        Args:
            logger: Logger to configure
            color_output: Whether to enable colored output
        """
        if color_output:
            # Use Rich handler for better formatting
            console_handler = RichHandler(
                console=self._console,
                show_time=False,
                show_path=False,
                rich_tracebacks=True,
                markup=True
            )
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            # Use standard handler
            console_handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
        
        console_handler.setLevel(getattr(logging, self.config.level))
        console_handler.addFilter(ContextFilter(color_output))
        logger.addHandler(console_handler)
    
    def _setup_file_handler(self, logger: logging.Logger) -> None:
        """Set up file logging handler.
        
        Args:
            logger: Logger to configure
        """
        # Ensure log directory exists
        log_file_path = Path(self.config.file_path)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file_path,
            maxBytes=self.config.max_file_size_mb * 1024 * 1024,
            backupCount=self.config.backup_count,
            encoding='utf-8'
        )
        
        # File formatter (no colors)
        file_formatter = logging.Formatter(self.config.format)
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(getattr(logging, self.config.level))
        
        logger.addHandler(file_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the configured settings.
        
        Args:
            name: Logger name
            
        Returns:
            Configured logger
        """
        # Use the base package name for consistency
        full_name = f"rhoai_security_manifest.{name}"
        
        if full_name not in self._loggers_configured:
            return self.setup_logging(full_name)
        
        return logging.getLogger(full_name)
    
    def set_level(self, level: str) -> None:
        """Change the logging level for all configured loggers.
        
        Args:
            level: New logging level
        """
        numeric_level = getattr(logging, level.upper())
        
        for logger_name in self._loggers_configured:
            logger = logging.getLogger(logger_name)
            logger.setLevel(numeric_level)
            
            # Update handler levels too
            for handler in logger.handlers:
                handler.setLevel(numeric_level)
    
    def add_context_filter(self, **context) -> None:
        """Add context information to all log records.
        
        Args:
            **context: Context key-value pairs to add
        """
        class CustomContextFilter(logging.Filter):
            def filter(self, record):
                for key, value in context.items():
                    setattr(record, key, value)
                return True
        
        for logger_name in self._loggers_configured:
            logger = logging.getLogger(logger_name)
            logger.addFilter(CustomContextFilter())


# Global logging manager instance
_logging_manager: Optional[LoggingManager] = None


def get_logger(name: str = "main") -> logging.Logger:
    """Get a configured logger instance.
    
    Args:
        name: Logger name suffix
        
    Returns:
        Configured logger
    """
    global _logging_manager
    
    if _logging_manager is None:
        from .config import get_config
        config = get_config()
        _logging_manager = LoggingManager(config.logging)
    
    return _logging_manager.get_logger(name)


def setup_logging(
    config: Optional[Config] = None,
    color_output: bool = True,
    quiet: bool = False
) -> logging.Logger:
    """Set up application logging.
    
    Args:
        config: Application configuration
        color_output: Whether to enable colored output
        quiet: Whether to suppress console output
        
    Returns:
        Main application logger
    """
    global _logging_manager
    
    if config is None:
        from .config import get_config
        config = get_config()
    
    _logging_manager = LoggingManager(config.logging)
    return _logging_manager.setup_logging(
        color_output=color_output,
        quiet=quiet
    )


def set_log_level(level: str) -> None:
    """Change the global logging level.
    
    Args:
        level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    global _logging_manager
    
    if _logging_manager is not None:
        _logging_manager.set_level(level)


def add_log_context(**context) -> None:
    """Add context information to all log records.
    
    Args:
        **context: Context key-value pairs to add
    """
    global _logging_manager
    
    if _logging_manager is not None:
        _logging_manager.add_context_filter(**context)


class LoggingContext:
    """Context manager for temporary logging context."""
    
    def __init__(self, **context):
        """Initialize with context data.
        
        Args:
            **context: Context key-value pairs
        """
        self.context = context
        self.filter = None
    
    def __enter__(self):
        """Add context filter."""
        class TempContextFilter(logging.Filter):
            def __init__(self, context):
                super().__init__()
                self.context = context
            
            def filter(self, record):
                for key, value in self.context.items():
                    setattr(record, key, value)
                return True
        
        self.filter = TempContextFilter(self.context)
        
        # Add filter to all configured loggers
        if _logging_manager:
            for logger_name in _logging_manager._loggers_configured:
                logger = logging.getLogger(logger_name)
                logger.addFilter(self.filter)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Remove context filter."""
        if self.filter and _logging_manager:
            for logger_name in _logging_manager._loggers_configured:
                logger = logging.getLogger(logger_name)
                logger.removeFilter(self.filter)


def log_function_call(logger: Optional[logging.Logger] = None):
    """Decorator to log function calls.
    
    Args:
        logger: Logger to use, defaults to function's module logger
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            func_logger = logger or get_logger(func.__module__.split('.')[-1])
            func_logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            
            try:
                result = func(*args, **kwargs)
                func_logger.debug(f"{func.__name__} completed successfully")
                return result
            except Exception as e:
                func_logger.error(f"{func.__name__} failed with error: {e}")
                raise
        
        return wrapper
    return decorator


def log_execution_time(logger: Optional[logging.Logger] = None):
    """Decorator to log function execution time.
    
    Args:
        logger: Logger to use, defaults to function's module logger
    """
    import time
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            func_logger = logger or get_logger(func.__module__.split('.')[-1])
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                func_logger.info(f"{func.__name__} executed in {execution_time:.2f} seconds")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                func_logger.error(f"{func.__name__} failed after {execution_time:.2f} seconds: {e}")
                raise
        
        return wrapper
    return decorator