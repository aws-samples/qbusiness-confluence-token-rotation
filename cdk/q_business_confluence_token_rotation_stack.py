import json
from datetime import datetime
from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_lambda as lambda_,
    aws_secretsmanager as secretsmanager,
    aws_events as events,
    aws_scheduler as scheduler,
    aws_sns as sns,
    aws_kms as kms,
    aws_logs as logs,
    aws_events_targets as targets,
    CfnParameter as CfnParameter,
    aws_iam as iam
)
from constructs import Construct
from cdk_nag import NagSuppressions

class QBusinessConfluenceTokenRotationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)        

        param_confluence_secret_arn = CfnParameter(self, "qbusinessConfluenceSecretArn",
                description="Target Qbusiness confluence secret arn"
            )
        param_rotation_schedule = CfnParameter(self, "confluenceSecretRotationSchedule",
                description="Qbusiness confluence secret rotation schedule (cron or rate)",
                default="cron(55 * * * ? *)"
            )
        
        param_email = CfnParameter(self, "qbusinessConfluenceSecretRotationEmail",
                                           description="Email address for QBusiness Confluence secret rotation notifications")
        
        param_notify_successful_rotation = CfnParameter(self, "sendSuccessfulRotationEmail", 
                                                         description="Send email notifications on successful rotation", 
                                                         default="True")
        
        param_notify_failed_rotations = CfnParameter(self, "sendFailedRotationEmail",
                                                         description="Send email notifications on failed rotation",
                                                         default="True")

        
        qbusiness_confluence_backup_secret = self.create_backup_secret()
        
        rotation_lambda = self.create_rotation_lambda(param_confluence_secret_arn, 
                                                      param_notify_successful_rotation, 
                                                      param_notify_failed_rotations, 
                                                      qbusiness_confluence_backup_secret)
        
        self.setup_rotation_schedule(param_rotation_schedule, rotation_lambda)
        
        self.setup_rotation_notifications(param_email)      

        CfnOutput(self, "QBusinessConfluenceBackupSecretName", 
                  value=qbusiness_confluence_backup_secret.name)
        CfnOutput(self, "QBusinessConfluenceRotationLambdaArn",
                  value=rotation_lambda.function_arn)

        self.add_nag_suppressions()

    
    
    def create_backup_secret(self):
        qbusiness_confluence_backup_secret = secretsmanager.CfnSecret(self, "qbusiness-confluence-backup-secret",
                secret_string = json.dumps({
                    "hostUrl": "hostUrl",
                    "confluenceAppKey": "confluenceAppKey",
                    "confluenceAppSecret": "confluenceAppSecret",
                    "confluenceAccessToken": "confluenceAccessToken",
                    "confluenceRefreshToken": "confluenceRefreshToken"
                }),
                name=f'QBusiness-Confluence-Backup-Secret',
                description = "QBusiness Confluence backup secret")
                
        return qbusiness_confluence_backup_secret

    
    
    def create_rotation_lambda(self, 
                               param_confluence_secret_arn, 
                               param_notify_successful_rotation, 
                               param_notify_failed_rotations, 
                               qbusiness_confluence_backup_secret):
        
        rotation_lambda_role = iam.Role(self, "qbusiness-confluence-secret-rotator-lambda-role",
                    role_name = f"QBsuiness-Confluence-secret-rotator-lambda-role",
                    assumed_by = iam.ServicePrincipal("lambda.amazonaws.com"),
                    managed_policies = [
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
                    ],
                    inline_policies = {
                        "QBusiness-Confluence-secret-rotator-policy": 
                            iam.PolicyDocument(                            
                                statements = [
                                    iam.PolicyStatement(
                                        actions = ["secretsmanager:DescribeSecret",
                                                "secretsmanager:GetSecretValue", 
                                                "secretsmanager:PutSecretValue",
                                                "secretsmanager:UpdateSecretVersionStage"],
                                        resources = [param_confluence_secret_arn.value_as_string,
                                                    qbusiness_confluence_backup_secret.attr_id]
                                    ),
                                    iam.PolicyStatement(
                                        actions = ["events:PutEvents"],
                                        resources = [f"arn:aws:events:{Stack.of(self).region}:{Stack.of(self).account}:event-bus/default"])
                                ]
                            )
                    }
                )
        
        rotation_lambda_dependencies = lambda_.LayerVersion(
                    self, 
                    "qbusiness-confluence-secret-rotation-lambda-dependencies",
                    layer_version_name="dependencies",
                    code=lambda_.Code.from_asset("src//lambda-layers//dependencies"),
                    compatible_runtimes=[lambda_.Runtime.PYTHON_3_11]                    
                )

        rotation_lambda = lambda_.Function(self, "qbusiness-confluence-secret-rotator",
                role=rotation_lambda_role,
                code=lambda_.Code.from_asset("src//lambda"),
                handler="rotation_lambda_function_caller.lambda_handler",
                runtime=lambda_.Runtime.PYTHON_3_11,
                environment={
                    "QBUSINESS_CONFLUENCE_SECRET_ID": param_confluence_secret_arn.value_as_string,
                    "QBUSINESS_CONFLUENCE_BACKUP_SECRET_ID": qbusiness_confluence_backup_secret.attr_id,
                    "SEND_SUCCESSFUL_ROTATION_EMAIL": param_notify_successful_rotation.value_as_string,
                    "SEND_FAILED_ROTATION_EMAIL": param_notify_failed_rotations.value_as_string
                },
                timeout=Duration.seconds(120),
                layers=[rotation_lambda_dependencies]
            )
        
        lambda_.CfnPermission(self, "events-permission-on-rotator-lambda",
            action="lambda:InvokeFunction",
            function_name=rotation_lambda.function_name,
            principal="events.amazonaws.com")
                    
        return rotation_lambda
    
    
    
    def setup_rotation_schedule(self, param_rotation_schedule, rotation_lambda):
        scheduler_role = iam.Role(self, "qbusiness-confluence-secret-rotation-scheduler-role",
                    role_name = f"QBusiness-Confluence-secret-rotation-scheduler-role",
                    assumed_by = iam.ServicePrincipal("scheduler.amazonaws.com"),
                    inline_policies = {
                        "confluence-secret-rotation-scheduler-policy":
                            iam.PolicyDocument(
                                statements = [
                                    iam.PolicyStatement(
                                        actions = ["lambda:InvokeFunction"],
                                        resources = [rotation_lambda.function_arn]
                                    )
                                ]
                            )
                    }
                )

        scheduler.CfnSchedule(self, "qbusiness-confluence-secret-rotation-scheduler",
                flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(
                    mode="OFF"
                ),
                schedule_expression=param_rotation_schedule.value_as_string,
                target=scheduler.CfnSchedule.TargetProperty(
                    arn=rotation_lambda.function_arn,
                    role_arn=scheduler_role.role_arn,
                    retry_policy=scheduler.CfnSchedule.RetryPolicyProperty(
                        maximum_retry_attempts=0,
                        maximum_event_age_in_seconds=5 * 60
                    )
                )
            )
        
    
    
    def setup_rotation_notifications(self, param_email):
        
        sns_key = kms.Key(self, "qbusiness-confuence-sns-key", enable_key_rotation=True)
        sns_key.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"],
            principals=[iam.ServicePrincipal("sns.amazonaws.com")],
            resources=["*"]
        ))
        sns_key.add_to_resource_policy(iam.PolicyStatement(
            actions=["kms:Decrypt",
                     "kms:GenerateDataKey*"],
            principals=[iam.ServicePrincipal("events.amazonaws.com")],
            resources=["*"]
        ))

        sns_topic = sns.Topic(self, 
                              "qbusiness-confluence-secret-rotation-events-topic",
                              display_name="QBusiness Confluence Secret Rotation Events Topic",
                              master_key=sns_key)
        
        sns.Subscription(self,
                         "qbusiness-confluence-secret-rotation-events-subscription",
                         endpoint=param_email.value_as_string,
                         protocol=sns.SubscriptionProtocol.EMAIL,
                         topic=sns_topic)        

        event_rule = events.Rule(self, "qbusiness-confluence-secret-rotation-events-rule",
                event_pattern=events.EventPattern(
                    source=["qbusiness.confluence.token_rotation"],
                    detail_type=["rotation_successful", "rotation_failed"]
                )
            )
        event_rule.add_target(targets.SnsTopic(sns_topic))
    
    
    
    def add_nag_suppressions(self):
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            "/QBusinessConfluenceTokenRotationStack/qbusiness-confluence-secret-rotator-lambda-role/Resource",
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "AWS Managed Policies [\"AWSLambdaBasicExecutionRole\"] are used.",
                }
            ])

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            "/QBusinessConfluenceTokenRotationStack/qbusiness-confluence-backup-secret",
            [
                {
                    "id": "AwsSolutions-SMG4",
                    "reason": '''The minimum interval at which the automatic rotations can be scheduled is once in 4 hours. 
                    Confluence tokens are valid only for an hour and need to be rotated every hour to make a valid access token available to the Q Business application.
                    Hence we are using eventbridge scheduler to trigger the rotation lambda in this solution 
                    (instead of automatic rotations).'''
                }
            ])