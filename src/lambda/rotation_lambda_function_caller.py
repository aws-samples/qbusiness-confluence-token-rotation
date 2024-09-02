#Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#SPDX-License-Identifier: MIT-0

import base64
import sys
import boto3
import logging
import os
import requests
from services.qbusiness_utils import confluence_refresh_token_flow
from services.qbusiness_utils.secrets_manager_helpers import *
from services.qbusiness_utils.confluence_helpers import QbusinessConfluenceTokenGeneratorArgs
from services.qbusiness_utils.confluence_helpers import QbusinessConfluenceTokenRefresherArgs
from services.qbusiness_utils.common import *
import json
import uuid
import rotation_lambda_function

logger = get_logger(__name__)

pending_version = None

steps = ['createSecret', 'setSecret', 'testSecret', 'finishSecret']

def lambda_handler(event, context):
    service_client = boto3.client('secretsmanager')
    arn = os.environ['QBUSINESS_CONFLUENCE_BACKUP_SECRET_ID']
    pending_version = get_secret_version_id_by_stage(arn, "AWSPENDING")
    logger.info(f'pending_version: {pending_version}')

    if pending_version == None:
        pending_version = str(uuid.uuid4())
    for step in steps:
        logger.info(f'step: {step}')
        event = {"SecretId": arn, "ClientRequestToken": pending_version, "Step": step}
        context = []
        rotation_lambda_function.lambda_handler(event, context)
        pass

if __name__ == "__main__":
    lambda_handler({}, [])