import boto3
import csv
import tempfile
import os
import json       
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # Initialize the Boto3 clients for CloudTrail and S3
    
    region= "us-east-2"       
    cloudtrail_client = boto3.client('cloudtrail',region_name=region)         
    s3_client = boto3.client('s3')
            
    # Define the username and the specific value for filtering   
    #username = 'trail102@gmail.com'         
    username = event['user_name']   
            
    # Retrieve all CloudTrail events matching the specified username
    events = []
    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': username
            }
        ]
    )
    events.extend(response['Events'])
            
    # Paginate through the remaining events using the NextToken
    while 'NextToken' in response:
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                        {
                            'AttributeKey': 'Username',
                            'AttributeValue': username
                        }
                    ],
                    NextToken=response['NextToken']
                )
        events.extend(response['Events'])
            
            # Generate a CSV file from the events
    csv_data = generate_csv(events)
            
            # Create a temporary file to store the CSV data
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(csv_data.encode('utf-8'))
    temp_file.close()
            
    s3_client.upload_file(temp_file.name, 'hiring-userlogs', 'logfiles/'+ username+'-logs.csv')   
            
            # Clean up the temporary file
    os.remove(temp_file.name)
            
    print("filtered events are uploaded to S3 bucket")
            
    sns = boto3.client('sns')     
    topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-userlogs-monitor-sns'
    message = f"Hi Admin \n\n Part of hiring infra setup the lambda [Hiring-Userlogs-Monitor] has been invoked and logs are uploade to s3 bucket hiring-userlogs \n"
    sns.publish(TopicArn=topic_arn, Message=message)
    
    
        
def generate_csv(events):
    # Generate a CSV string from the events list
    csv_data = ''
    fieldnames = ['EventTime', 'EventName', 'Username', 'EventRecord']
        
    with tempfile.TemporaryFile(mode='w+', newline='') as temp_file:
        csv_writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
        csv_writer.writeheader()
            
        for event in events:
            event_data = {
                'EventTime': event['EventTime'].strftime("%Y-%m-%d %H:%M:%S"),
                'EventName': event['EventName'],
                'Username': event['Username'],
                'EventRecord': json.dumps(event, default=json_serializable)        
            }
            csv_writer.writerow(event_data)
            
        temp_file.seek(0)
        csv_data = temp_file.read()     
        
    return csv_data
        
def json_serializable(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')
        
   
    
        
