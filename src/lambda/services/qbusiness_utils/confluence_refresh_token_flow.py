import logging
import time, requests, json
from urllib.parse import urlparse, parse_qs, urlencode, quote
from services.qbusiness_utils.args_helpers import get_refresher_parsed_args, validate_args
from services.qbusiness_utils.confluence_helpers import *
from services.qbusiness_utils.common import *
from services.qbusiness_utils.secrets_manager_helpers import *

logger = get_logger(__name__)

def refresh_tokens(secret:QbusinessConfluenceSecret):
    logger.info("------------Renewing access token------------")
    confluence_oauth_params = ConfluenceOAuthParameters()
    url = confluence_oauth_params.oauth_token_url
    headers = {'Content-Type': 'application/json'}
    payload = f"{{\"grant_type\": \"refresh_token\", \"client_id\": \"{secret.confluenceAppKey}\", \"client_secret\": \"{secret.confluenceAppSecret}\", \"refresh_token\": \"{secret.confluenceRefreshToken}\"}}"

    response = requests.post(confluence_oauth_params.oauth_token_url, json=json.loads(payload), headers=headers, timeout=10)
    json_response = json.loads(response.text)    

    if response.status_code == 200:
        logger.info("------------Received auth_token and refresh_token------------")        
    else:
        raise Exception(f"Failed to renew access token using refresh_token: {response.json()}")
    
    return json_response
   

if __name__ == "__main__":
    parsed_args = get_refresher_parsed_args()
    validate_args(parsed_args, 'refresh')
    args = QbusinessConfluenceTokenRefresherArgs(
        secret_name= parsed_args.secret_name, 
        save_tokens_to_file=parsed_args.save_tokens_to_file
    )
    secret = get_secret_by_id(args.secret_name)
    json_response =  refresh_tokens(secret) 
    secret.confluenceAccessToken = json_response['access_token']
    secret.confluenceRefreshToken = json_response['refresh_token']
    secret_pending_version_id = create_new_version(args.secret_name, secret, "AWSPENDING")
    rotate_pending_secret_version(args.secret_name, secret_pending_version_id)
    exit(0)