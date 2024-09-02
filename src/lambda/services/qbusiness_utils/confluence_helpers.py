from urllib.parse import urlencode, quote
from services.qbusiness_utils.common import constants
import json
import requests


def test_access_token(access_token):
    url = f"{constants.confluence.CONFLUENCE_API_ROOT_URL}/oauth/token/accessible-resources"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, timeout=10)
    return response


class QbusinessConfluenceTokenGeneratorArgs:
    def __init__(self, secret_name, username, password, redirect_url, state="", use_headless_chrome:bool = True, save_tokens_to_file = False):
        self.secret_name = secret_name
        self.username = username
        self.password = password
        self.redirect_url = redirect_url
        self.state = state
        self.use_headless_chrome = use_headless_chrome
        self.save_tokens_to_file = save_tokens_to_file

class QbusinessConfluenceTokenRefresherArgs:
    def __init__(self, secret_name, backup_secret_name, save_tokens_to_file = False):
        self.secret_name = secret_name
        self.backup_secret_name = backup_secret_name
        self.save_tokens_to_file = save_tokens_to_file

class QbusinessConfluenceSecret(dict):
    def __init__(self, confluenceAppKey, confluenceAppSecret,
                  confluenceAccessToken, confluenceRefreshToken, hostUrl):
        self.confluenceAppKey = confluenceAppKey
        self.confluenceAppSecret = confluenceAppSecret
        self.confluenceAccessToken = confluenceAccessToken
        self.confluenceRefreshToken = confluenceRefreshToken
        self.hostUrl = hostUrl

class ConfluenceOAuthParameters:
    def __init__(self):
        self.oauth_authorization_url = f"{constants.confluence.CONFLUENCE_AUTH_ROOT_URL}/authorize"
        self.oauth_token_url = f"{constants.confluence.CONFLUENCE_AUTH_ROOT_URL}/oauth/token"
        self.audience = constants.confluence.CONFLUENCE_OAUTH_AUDIENCE
        self.response_type = "code"
        self.prompt = "consent"
        self.scopes = ["read:content:confluence",
                "read:content-details:confluence",
                "read:space-details:confluence",
                "read:audit-log:confluence",
                "read:page:confluence",
                "read:attachment:confluence",
                "read:blogpost:confluence",
                "read:custom-content:confluence",
                "read:comment:confluence",
                "read:template:confluence",
                "read:label:confluence",
                "read:watcher:confluence",
                "read:group:confluence",
                "read:relation:confluence",
                "read:user:confluence",
                "read:configuration:confluence",
                "read:space:confluence",
                "read:space.permission:confluence",
                "read:space.property:confluence",
                "read:user.property:confluence",
                "read:space.setting:confluence",
                "read:analytics.content:confluence",
                "read:content.permission:confluence",
                "read:content.property:confluence",
                "read:content.restriction:confluence",
                "read:content.metadata:confluence",
                "read:inlinetask:confluence",
                "read:task:confluence",
                "read:permission:confluence",
                "read:whiteboard:confluence",
                "read:database:confluence",
                "read:embed:confluence",
                "read:app-data:confluence",
                "offline_access"]
        
    def build_authz_url(self, client_id, redirect_url, state):
        query = {
            'audience': self.audience,
            'client_id': client_id,
            'scope': ' '.join(self.scopes),
            'redirect_uri': redirect_url,
            'state': state,
            'response_type': self.response_type,
            'prompt': self.prompt
        }
        return f"{self.oauth_authorization_url}?{urlencode(query, quote_via=quote)}"