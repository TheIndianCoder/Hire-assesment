import boto3
from botocore.exceptions import ClientError      
import time
region_name = 'us-east-2'
region_names = ['us-east-2', 'us-east-1']

def lambda_handler(event, context):

    ec2 = boto3.client('ec2', region_name=region_name)      
    sns = boto3.client('sns',region_name=region_name)
    
    tag_key = 'Owner'   
    #tag_value = 'Hiring-1'                                                     
    tag_value = event['user_name']     
  
    try:        
         
        stopped_resources = []
        
        filters = [{'Name': 'tag-key', 'Values': [tag_key]}, {'Name': 'tag-value', 'Values': [tag_value]}]
        
        ec2 = boto3.client('ec2', region_name=region_name)
        instances = ec2.describe_instances(Filters=filters)
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:       
                instance_id = instance['InstanceId']
                try:
                    ec2.stop_instances(InstanceIds=[instance_id])    
                    print(f"stopped instance {instance_id}")
                    stopped_resources.append(instance_id)
                except ClientError as e:
                    print(f"Error stopping instance {instance_id}: {e}")
        

        formatted_stopped_resources = [f"{i}. {resource}" for i, resource in enumerate(stopped_resources, start=1)]    
        
        sns = boto3.client('sns')
        topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-Ec2-autostop-sns'
        message = f"Hi Admin,\n\nPart of the hiring infra setup, the lambda function 'Hiring-Ec2-autostop' has been invoked.\nAll existing ec2 instances created by the user : [{tag_value}] are stopped."
        message += f"\nThe list of stopped EC2 instances are:\n"
        message += "\n".join(formatted_stopped_resources)
        message += f"\n\nIn order to evaluate the resources the L2 panel team has to start the instance manually"
        
        sns.publish(TopicArn=topic_arn, Message=message)
        
    except ClientError as e:      
        sns = boto3.client('sns')
        topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-Resource-Termination-sns'
        message = f"Hi Admin \n\n Part of hiring infra setup the lambda [Hiring-Ec2-autostop] has faced an error \n\n{e}"
        sns.publish(TopicArn=topic_arn, Message=message)
            
            
            

