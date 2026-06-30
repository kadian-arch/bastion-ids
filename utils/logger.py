import logging
import os
from config.settings import BASE_DIR
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import MODELS, ENCODERS

def setup_bastion_logger():
    log_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger("BastionIDS")
    logger.setLevel(logging.INFO)
    
    # File Handler
    file_handler = logging.FileHandler(os.path.join(log_dir, "system.log"))
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    return logger

# Global instance
logger = setup_bastion_logger()