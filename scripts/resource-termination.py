import boto3
from botocore.exceptions import ClientError      
import time
region_name = 'us-east-2'
region_names = ['us-east-2', 'us-east-1']

def lambda_handler(event, context):

    
    ec2 = boto3.client('ec2', region_name=region_name)      
    events = boto3.client('events',region_name=region_name)              
    sns = boto3.client('sns',region_name=region_name)
    elbv2 = boto3.client('elbv2',region_name=region_name)   
    lambda_client = boto3.client('lambda',region_name=region_name)
    
    try:
        
        resource_list = []        
        tag_key = 'Owner'   
        #tag_value = 'Hiring-1'                                        
        tag_value = event['user_name']              
        
        # call the get_resources method to retrieve all resources with the specified tag
        for region in region_names:
            client = boto3.client('resourcegroupstaggingapi', region_name=region)
            
            response = client.get_resources(
                TagFilters=[
                    {
                        'Key': tag_key,
                        'Values': [tag_value]
                    }
                ]
            )
            
            resource_list.extend([resource['ResourceARN'] for resource in response['ResourceTagMappingList']])     
        
        formatted_list = [f"{i}. {resource}" for i, resource in enumerate(resource_list, start=1)]
        deleted_resources = []

        
        # upload the list of resources to an S3 bucket
        s3 = boto3.client('s3')
        bucket_name = 'hiring-userlogs'
        object_key = 'Resource-list/' + tag_value +'-resource-list.txt'
        Content = '\n'.join(resource_list)
        s3.put_object(Body=Content, Bucket=bucket_name, Key=object_key)
        
        filters = [{'Name': 'tag-key', 'Values': [tag_key]}, {'Name': 'tag-value', 'Values': [tag_value]}]
        
        ec2 = boto3.client('ec2', region_name=region_name)
        instances = ec2.describe_instances(Filters=filters)
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                try:
                    ec2.terminate_instances(InstanceIds=[instance_id])
                    print(f"Terminated instance {instance_id}")
                    deleted_resources.append(instance_id)
                except ClientError as e:
                    print(f"Error terminating instance {instance_id}: {e}")
                
        volumes = ec2.describe_volumes(Filters=filters)
        for volume in volumes['Volumes']:
            volume_id = volume['VolumeId']
            try:
                ec2.delete_volume(VolumeId=volume_id)
                print(f"Deleted volume {volume_id}")
                deleted_resources.append(volume_id)
            except ClientError as e:
                    print(f"Error in deleting the volumes :{e}")
        
            
        images = ec2.describe_images(Filters=filters)
        for image in images['Images']:
            image_id = image['ImageId']
            try:
                ec2.deregister_image(ImageId=image_id)
                print(f"Deregistered AMI {image_id}")
                deleted_resources.append(image_id)
            except ClientError as e:
                    print(f"Error in deleting the AMI :{e}")
                    
                    
        for resource_arn in resource_list:        
            if resource_arn.startswith("arn:aws:elasticloadbalancing:us-east-2:167854621873:loadbalancer"):
                print(f"resource_arn")
                lb_name = resource_arn.split('/')[-2]
                try:
                    elbv2.delete_load_balancer(LoadBalancerArn=resource_arn)
                    print(f"Deleted load balancer {lb_name}")
                    deleted_resources.append("load-balancer-"+lb_name)
                except ClientError as e:
                    print(f"Error in deleting the load balancer:{e}") 
                    
        for resource_arn in resource_list:
            
            if resource_arn.startswith("arn:aws:events:"):
                print(f"ARN is {resource_arn}")
                event_name = resource_arn.split('/')[-1]
                print(event_name)
                  
                try:
                    events.delete_rule(Name=event_name)
                    print(f"Deleted rule {event_name}")
                    deleted_resources.append(resource_arn)
                except ClientError as e:
                    print(f"Error in deleting the event rule:{e}")
        

        for resource_arn in resource_list:        
            if resource_arn.startswith("arn:aws:sns:"):
                print(F"arn is {resource_arn}")
                topic_name = resource_arn.split('/')[-1]
                print(topic_name)
                try:
                    sns.delete_topic(TopicArn=resource_arn)
                    print(f"Deleted topic {topic_name}")
                    deleted_resources.append("sns-topic-"+ topic_name)
                except ClientError as e:
                    print(f"Error in deleting sns topic:{e}")    
        
        for resource_arn in resource_list:        
            if resource_arn.startswith("arn:aws:s3:"):
                # Delete S3 bucket
                print(f"ARN is {resource_arn}")
                bucket_name = resource_arn.split(':::')[-1]
                print(bucket_name)
                try:
                    s3.delete_bucket(Bucket=bucket_name)
                    print(f"Deleted bucket {bucket_name}")
                    deleted_resources.append("bucket-name"+bucket_name)
                except ClientError as e:
                    print(f"Error in s3 bucket:{e}") 
                
        for resource_arn in resource_list:
            if resource_arn.startswith("arn:aws:lambda"):
                print(f"resource_arn")
                lambda_name = resource_arn.split('/')[-1]
                try:
                    lambda_client.delete_function(FunctionName=lambda_name)
                    print(f"Deleted the lambda {lambda_name}")
                    deleted_resources.append("lambda-function"+lambda_name)
                except ClientError as e:
                    print(f"Error in lambda function:{e}") 
        
        for resource_arn in resource_list:    
            if resource_arn.startswith("arn:aws:elasticloadbalancing:us-east-2:167854621873:targetgroup"):
                print(f"resource_arn")
                tg_name = resource_arn.split('/')[-2]
                try:
                    elbv2.delete_target_group(TargetGroupArn=resource_arn)
                    print(f"Deleted target group {tg_name}")
                    deleted_resources.append("target group-"+tg_name)
                except ClientError as e:
                    print(f"Error in target group:{e}") 
        
        time.sleep(60) 
        security_groups = ec2.describe_security_groups(Filters=filters)
        for security_group in security_groups['SecurityGroups']:
            group_id = security_group['GroupId']
            try:
                ec2.delete_security_group(GroupId=group_id)
                print(f"Deleted security group {group_id}")
                deleted_resources.append(group_id)
            except ClientError as f:
                print(f"Error in deleting the security group :{f}")   
            
        formatted_deleted_resources = [f"{i}. {resource}" for i, resource in enumerate(deleted_resources, start=1)]
        s3.put_object(Body='\n'.join(formatted_deleted_resources), Bucket=bucket_name, Key='Resource-list/' + tag_value +'-deleted_resources.txt')            
        sns = boto3.client('sns')
        topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-Resource-Termination-sns'
        message = f"Hi Admin,\n\nPart of the hiring infra setup, the lambda function 'Hiring-Resource-Termination' has been invoked.\nAll existing resources created by the user are deleted.\n\nThe list of resources created are:\n"
        message += "\n".join(formatted_list)
        
        message += f"\n\nThe list of deleted resources are:\n"
        message += "\n".join(formatted_deleted_resources)
        
        sns.publish(TopicArn=topic_arn, Message=message)
        
    except ClientError as e:
            #print(e)           
        sns = boto3.client('sns')
        topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-Resource-Termination-sns'
        message = f"Hi Admin \n\n Part of hiring infra setup the lambda [Hiring-Resource-Termination] has faced an error \n\n{e}"
        sns.publish(TopicArn=topic_arn, Message=message)
            
            
            

