import logging
import sys
from typing import Optional


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Setup and configure logger."""
    logger = logging.getLogger('security_scanner')
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    return logger