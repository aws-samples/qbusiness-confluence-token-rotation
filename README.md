# Amazon Q Business OAuth token rotation for Confluence data source

[Amazon Q Business](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/what-is.html) works with number of data sources including Confluence. For more details on Q Business Confluence cloud connector please see the [page](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/confluence-cloud-connector.html). With Confluence data source we can use basic/OAuth authentication.  

When OAuth is used, Q Business starts sync with the provided access token. When the access token expires, Q Business obtains a new access token using the provided refresh token to continue with the sync. [Confluence](https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/) uses rotating refresh tokens with limited life time, hence every time a new access token is obtained using a refresh token, Confluence returns new pair of access and refresh tokens which are not saved back to the QBusiness secret - Hence the subsequent syncs fail.  

This repo implements a solution using AWS Lambda and Amazon EventBridge to generate new access tokens using refresh token for Confluence data source.

An additonal backup secret is used to store the refresh token which is then used in generating new access/refresh tokens pair hourly - thus obtained new access token is then copied to the secret used by the Q Business Confluence data source. New refresh tokens are not copied into Q Business secret to avoid refresh token invalidation when Q Business tries to obtain a new access token. Only a placeholder refresh token (confluenceRefreshToken) is copied to the Q Business secret.

Emails are sent on successful/failed token roations.

This repository provides a sample for rotating Q Business Confluence tokens and is not production ready. It is your responsibility as a developer to test and vet the application according to your security guidlines.

## Architecture

![Amazon Q Busines Confluence token rotation!](/images/architecture.png "Amazon Q Busines Confluence token rotation")

The main functionality of this application is to rotate the OAuth access token and refresh token for a Confluence data source used by Amazon Q Business.

- The rotation process is triggered by a scheduled AWS Lambda function invocation, and the different steps of the rotation (create, set, test, and finish) are handled by separate functions within the Lambda handler.
- Lambda function performs the following tasks:
    - **Obtain a new access token and refresh token :** The Lambda function uses the existing refresh token stored in a backup AWS Secrets Manager secret to obtain a new access token and refresh token from Confluence's OAuth server.
    - **Update the backup secret :** The new access token and refresh token obtained in step 1 are stored in the backup secret.
    - **Update the Q Business Confluence secret :** The Lambda function updates the Q Business Confluence secret (used by the Q Business application to authenticate with Confluence) with the new access token obtained in step 1. However, it does not update the refresh token in this secret to avoid token invalidation when Q Business tries to obtain a new access token during a sync operation.
    - **Send notifications :** The Lambda function sends notifications via Amazon EventBridge on successful or failed secret rotations.
- Sequence diagram
    - ![Sequence Diagram](/images/sequence_diagram.png)


## Getting Started

### Prerequisites:
- Please ensure that your Q Business application has been deployed and configured with a Confluence data source. 
- Make a note of the arn of the secret you have setup while configuring your Confluence data source (which you will use in step 2). 
- Also make sure that no sync job is running against the Confluence data source.

### Steps:
1. Restore files for the dependencies Lambda layer using [install_layers.bat](/src/install_layers.bat)

2. Deploy CDK stack with the parameters

```
    cdk deploy 
    --parameters qbusinessConfluenceSecretArn="targetQbusinessConfluenceSecretArn"
    --parameters qbusinessConfluenceSecretRotationEmail="emailAddress"
```

Emails are sent on both successful/failed token roations. To turn off emails on successful rotations provide an additonal parameter.

```
    --parameters sendSuccessfulRotationEmail="False"
```

3. Deployed CDK stack creates a new secret **QBusiness-Confluence-Backup-Secret**. Update it with Confluence OAuth credentials

```
    {
        "confluenceAppKey": "confluenceAppKeyValue",
        "confluenceAppSecret": "confluenceAppSecretValue",
        "confluenceAccessToken": "confluenceAccessTokenValue",
        "confluenceRefreshToken": "confluenceRefreshTokenValue",
        "hostUrl": "https://example.atlassian.net"
    }
```

4. Confirm subscription to the deployed SNS topic (using link sent in an email to the emailAddress which was provided as a cdk  parameter)

5. Deployed application fetches a new pair of access/refresh tokens using refresh token every hour, updates the access token in the Q Business Confluence secret. New access/refresh token pair is also saved into the back up secret for obtaining new tokens during next iteration. You will receive email notifications on successful/failed secret rotations.

## Notes

- For syncs that run shorter than an hour, every time a new access token will be available valid for the next one hour. So the sync will succeed with out errors.

- For syncs that run longer than an hour, QBusiness tries to obtain an access token when the token has expired. Because a dummy/placeholder refresh token is provided (explained above), the sync operation stops with an error (invalid token). However QBusiness continues with next iteration of sync as the new access token would be available then. Please ensure that the "New, modified, or deleted content sync" sync mode is selected.

![Amazon Q Busines Sync mode!](/images/sync_mode.png "New, modified, or deleted content sync")

- Default rotation is scheduled for 55th minute every hour cron(55 * * * ? *). This works well if you select your sync schedule to start at the beginning of the hour (hourly/10AM every day etc). 

- If you need to schedule syncs for times other than the begnning of the hour, you could override the default token rotation schedule by passing a CDK param.

```
    --parameters confluenceSecretRotationSchedule="cron-or-rate-expression"
```

## Clean up

- To delete the application either run the below command
```
    cdk destroy
```
- Or delete the stack from CloudFormation stacks page on AWS Console

![Delete stack from AWS console](/images/delete_stack.png)



## References

1. [Confluence OAuth 2.0 apps](https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/)
2. [How do I get a new access token, if my access token expires or is revoked?](https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/#how-do-i-get-a-new-access-token--if-my-access-token-expires-or-is-revoked-)
3. [Connecting Amazon Q Business to Confluence (Cloud)](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/confluence-cloud-console.html)
3. [How Amazon Q works with Confluence (Cloud) access and refresh tokens](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/confluence-cloud-credentials-notes.html)
4. [AWS Secrets Manager - Lambda rotation functions](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html)