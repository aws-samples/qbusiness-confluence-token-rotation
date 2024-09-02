# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import base64
import sys
import boto3
import logging
import os

from services.qbusiness_utils import confluence_refresh_token_flow
from services.qbusiness_utils.secrets_manager_helpers import *
from services.qbusiness_utils.eventbridge_helpers import *
from services.qbusiness_utils.confluence_helpers import QbusinessConfluenceTokenGeneratorArgs
from services.qbusiness_utils.common import constants

import json

logger = get_logger(__name__)

def lambda_handler(event, context):
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    arn = event['SecretId']
    clientRequestToken = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    
    # if not metadata['RotationEnabled']:
    #     logger.error("Secret %s is not enabled for rotation" % arn)
    #     raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']    
    #validate_version(versions, token, arn)

    if step == "createSecret":
        create_secret(service_client, arn, clientRequestToken)
    elif step == "setSecret":
        set_secret(service_client, arn, clientRequestToken)
    elif step == "testSecret":
        test_secret(service_client, arn, clientRequestToken)
    elif step == "finishSecret":
        finish_secret(service_client, arn, clientRequestToken)
    else:
        raise ValueError("Invalid step parameter")

def validate_version(versions, token, arn):
    if token not in versions:
        error_msg = f"Secret version {token} has no stage for rotation of secret {arn}."
        logger.error(error_msg)
        raise ValueError(error_msg)

    if constants.secret_stages.AWSCURRENT in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return True

    if constants.secret_stages.AWSPENDING not in versions[token]:
        error_msg = f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        logger.error(error_msg)
        raise ValueError(error_msg)

    return False

def create_secret(service_client, arn, clientRequestToken):
    """Create the secret

    This method first checks for the existence of a secret for the passed in clientRequestToken. 
    If one does not exist, it will generate a new secret and put it with the passed in clientRequestToken.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        clientRequestToken (string): The clientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    secret_response = service_client.get_secret_value(SecretId=arn, VersionStage=constants.secret_stages.AWSCURRENT)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, 
                                        VersionId=clientRequestToken, 
                                        VersionStage=constants.secret_stages.AWSPENDING)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except Exception as e:
        # Put the secret
        backup_secret = create_new_tokens(service_client, arn)
        service_client.put_secret_value(SecretId=arn, 
                                        ClientRequestToken=clientRequestToken, 
                                        SecretString=json.dumps(backup_secret.__dict__), 
                                        VersionStages=[constants.secret_stages.AWSPENDING])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, clientRequestToken))          


def set_secret(service_client, arn, clientRequestToken):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. 
    For example, if the secret is a database  credential, this method should take the value of the AWSPENDING secret and
    set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        clientRequestToken (string): The ClientRequestToken associated with the secret version

    """
    try:
        backup_secret_response = service_client.get_secret_value(
                                        SecretId=arn, 
                                        VersionStage=constants.secret_stages.AWSPENDING)
        
        backup_secret_json = json.loads(backup_secret_response["SecretString"])

        secret_response = service_client.get_secret_value(
            SecretId=os.environ[constants.env.QBUSINESS_CONFLUENCE_SECRET_ID],
            VersionStage=constants.secret_stages.AWSCURRENT)
        
        secret_json = json.loads(secret_response["SecretString"])

        secret_json['confluenceAccessToken'] = backup_secret_json['confluenceAccessToken']
        secret_json['confluenceRefreshToken'] = 'confluenceRefreshToken'

        client_request_token = str(uuid.uuid4())
        service_client.put_secret_value(
            SecretId=os.environ[constants.env.QBUSINESS_CONFLUENCE_SECRET_ID], 
            SecretString=json.dumps(secret_json), 
            ClientRequestToken=client_request_token, 
            VersionStages=[constants.secret_stages.AWSPENDING])
    
        logger.info("setSecret: Successfully set secret for %s." % os.environ[constants.env.QBUSINESS_CONFLUENCE_SECRET_ID])
    except Exception as e:
        error_msg = "setSecret: Failed to set secret for %s. Error: %s" % (arn, e)
        publish_rotation_failed_event(arn, error_msg)
        logger.error(error_msg)   



def test_secret(service_client, arn, clientRequestToken):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. 
    For example, if the secret is a database credential, this method should validate that the user can login with the password
    in AWSPENDING and that the user has all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        clientRequestToken (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be tested against the service
    secret_name = os.environ[constants.env.QBUSINESS_CONFLUENCE_SECRET_ID]
    secret = get_secret_by_version_stage(secret_name, constants.secret_stages.AWSPENDING)
    test_response = test_access_token(secret.confluenceAccessToken)
    if(test_response.status_code == 200):
        logger.info("testSecret: Successfully tested secret for %s." % arn)
        logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (clientRequestToken, secret_name))
    else:
        raise Exception("Failed to test secret")


def finish_secret(service_client, arn, clientRequestToken):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        clientRequestToken (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    try:
        rotate_pending_secret_version(arn, clientRequestToken)
        logger.info("finishSecret-1: Successfully set AWSCURRENT stage to version %s for secret %s." % (clientRequestToken, arn))

        if os.environ[constants.env.SEND_SUCCESSFUL_ROTATION_EMAIL] == "True":
            publish_rotation_succeded_event(arn)

        secret_name = os.environ[constants.env.QBUSINESS_CONFLUENCE_SECRET_ID]
        secret_version = get_secret_version_id_by_stage(secret_name, constants.secret_stages.AWSPENDING)
        rotate_pending_secret_version(secret_name, secret_version)

        if os.environ[constants.env.SEND_SUCCESSFUL_ROTATION_EMAIL] == "True":
            publish_rotation_succeded_event(secret_name)

        logger.info("finishSecret-2: Successfully set AWSCURRENT stage to version %s for secret %s." % (secret_version, secret_name))

    except Exception as e:
        error_msg = "finishSecret: Failed to set secret for %s. Error: %s" % (arn, e)
        publish_rotation_failed_event(arn, error_msg)
        logger.error(error_msg)


def create_new_tokens(service_client, arn):
    logger.info("Trying to get tokens using refresh tokens")
    try:
        backup_secret = create_tokens_using_refresh_token(arn)
        return backup_secret
    except Exception as e:
        error_msg = f"Exception occurred while creating new tokens using refresh token: {str(e)}"
        logger.error(error_msg)
        publish_rotation_failed_event(arn, error_msg)
        raise Exception(e)
    
def create_tokens_using_refresh_token(arn):
    backup_secret = get_secret_by_id(arn)
    json_response =  confluence_refresh_token_flow.refresh_tokens(backup_secret)
    backup_secret.confluenceAccessToken = json_response['access_token']
    backup_secret.confluenceRefreshToken = json_response['refresh_token']       
    return backup_secret

if __name__ == "__main__":
    lambda_handler({}, [])