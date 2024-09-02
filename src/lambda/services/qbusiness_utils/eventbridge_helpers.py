import boto3

def publish_rotation_succeded_event(secret_id):
    client = boto3.client('events')    
    eventsresponse = client.put_events(
        Entries=[{ 
            'Source': 'qbusiness.confluence.token_rotation', 
            'Resources': [f'{secret_id}'],
            'DetailType': 'rotation_successful', 
            'Detail': '{ "mydata": "sampledata" }', 
            'EventBusName': 'default' 
        }]
    )

def publish_rotation_failed_event(secret_id, error_message):
    client = boto3.client('events')
    eventsresponse = client.put_events(
        Entries=[{
            'Source': 'qbusiness.confluence.token_rotation',
            'Resources': [f'{secret_id}'],
            'DetailType': 'rotation_failed',
            'Detail': '{ "error": "' + error_message + '" }',
            'EventBusName': 'default'
        }]
    )