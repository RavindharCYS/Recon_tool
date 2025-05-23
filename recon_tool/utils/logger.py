"""
Logger module - configure and retrieve loggers
"""
import logging
import sys
import os
from datetime import datetime
from typing import Optional

from .. import config

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def setup_logger(verbosity: int = config.VerbosityLevel.NORMAL) -> None:
    """
    Configure the logging system.
    
    Args:
        verbosity: Verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug)
    """
    # Map verbosity level to logging level
    log_levels = {
        config.VerbosityLevel.QUIET: logging.ERROR,
        config.VerbosityLevel.NORMAL: logging.INFO,
        config.VerbosityLevel.VERBOSE: logging.INFO,
        config.VerbosityLevel.DEBUG: logging.DEBUG
    }
    log_level = log_levels.get(verbosity, logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler if verbosity is high enough
    if verbosity >= config.VerbosityLevel.VERBOSE:
        # Create log directory if it doesn't exist
        log_dir = os.path.join(config.CONFIG_DIR, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'reconpy_{timestamp}.log')
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        logging.info(f"Detailed logs will be saved to {log_file}")

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__ of the calling module)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)