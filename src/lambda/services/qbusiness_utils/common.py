import datetime, time
import io
import json
import logging
from datetime import datetime

def get_logger(module_name, log_level = logging.INFO):
    handler = logging.StreamHandler()
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger = logging.getLogger(module_name)
    logger.setLevel(log_level)
    logger.addHandler(handler)
    return logger

logger = get_logger(__name__)

def save_tokens_to_file(json_response):
    try:
        json_filename = datetime.now().strftime("%d-%b-%Y-%H:%M:%S").replace(':', '-')+'.json'
        with io.open(json_filename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(json_response, indent=4))
            f.close()
        logger.info(f"------------Tokens saved to {json_filename}------------")
    except Exception as e:
        logger.error(f"Error saving tokens to file: {e}")

class constants:
    class secret_stages:
        AWSCURRENT = "AWSCURRENT"
        AWSPENDING = "AWSPENDING"
    class env:
        QBUSINESS_CONFLUENCE_SECRET_ID = "QBUSINESS_CONFLUENCE_SECRET_ID"
        QBUSINESS_CONFLUENCE_BACKUP_SECRET_ID = "QBUSINESS_CONFLUENCE_BACKUP_SECRET_ID"
        QBUSINESS_CONFLUENCE_REDIRECT_URL = "QBUSINESS_CONFLUENCE_REDIRECT_URL"
        SEND_SUCCESSFUL_ROTATION_EMAIL = "SEND_SUCCESSFUL_ROTATION_EMAIL"
        SEND_FAILED_ROTATION_EMAIL = "SEND_FAILED_ROTATION_EMAIL"
    class confluence:
        CONFLUENCE_AUTH_ROOT_URL = "https://auth.atlassian.com"
        CONFLUENCE_API_ROOT_URL = "https://api.atlassian.com"
        CONFLUENCE_OAUTH_AUDIENCE = "api.atlassian.com"


