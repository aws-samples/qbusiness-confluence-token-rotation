import logging
import uuid
import boto3, json
from services.qbusiness_utils.common import *
from services.qbusiness_utils.confluence_helpers import *

logger = logging.getLogger("")

def get_secret_by_id(secret_id):
    return get_secret_by_version_stage(secret_id)

def get_secret_by_version_stage(secret_id, version_stage = 'AWSCURRENT'):
    secrets_manager_client = boto3.client('secretsmanager')
    secret_response = secrets_manager_client.get_secret_value(SecretId=secret_id, VersionStage=version_stage)
    secret = json.loads(secret_response['SecretString'])
    return QbusinessConfluenceSecret(confluenceAppKey=secret['confluenceAppKey'],
                                    confluenceAppSecret=secret['confluenceAppSecret'],
                                    confluenceAccessToken=secret['confluenceAccessToken'],
                                    confluenceRefreshToken=secret['confluenceRefreshToken'],
                                    hostUrl=secret['hostUrl'])

def get_secret_version_id_by_stage(secret_id, version_stage):
    secrets_manager_client = boto3.client('secretsmanager')
    metadata = secrets_manager_client.describe_secret(SecretId=secret_id)
    versions = metadata['VersionIdsToStages']
    stage_vesrion_id = None
    for version in versions:
        if version_stage in versions[version]:
            stage_vesrion_id = version
            break
    return stage_vesrion_id

def rotate_pending_secret_version(secret_id, pending_version_id):
    secrets_manager_client = boto3.client('secretsmanager')
    current_version_id = get_secret_version_id_by_stage(secret_id, constants.secret_stages.AWSCURRENT)

    # Stage the new secret version
    secrets_manager_client.update_secret_version_stage(SecretId=secret_id, 
                                               VersionStage="AWSCURRENT", 
                                               MoveToVersionId=pending_version_id, 
                                               RemoveFromVersionId=current_version_id)
    
    secrets_manager_client.update_secret_version_stage(SecretId=secret_id, 
                                               VersionStage="AWSPENDING", 
                                               RemoveFromVersionId=pending_version_id)

def create_new_version(secret_id, secret:QbusinessConfluenceSecret, version_stage):
    logger.info("------------Updating secret in AWS Secrets Manager------------")
    secrets_manager_client = boto3.client('secretsmanager')
    
    #create new secret with AWSPENDING label
    client_request_token = str(uuid.uuid4())
    response = secrets_manager_client.put_secret_value(
        SecretId=secret_id,
        SecretString=json.dumps(secret.__dict__),
        ClientRequestToken = client_request_token,
        VersionStages=['AWSPENDING']
    )
    return client_request_token