import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
        
        try:
            
            user_name = event['user_name']
            #user_name = 'errortest2'
            print('Input data:', user_name) 
               
            region = 'us-east-2'
            ec2 = boto3.client('ec2', region_name=region)
            tag_key = "Owner"
            tag_value = user_name
            
            
            filters = [{'Name': 'tag-key', 'Values': [tag_key]}, {'Name': 'tag-value', 'Values': [tag_value]}]
            security_groups = ec2.describe_security_groups(Filters=filters)
            for security_group in security_groups['SecurityGroups']:
                group_id = security_group['GroupId']
                group = ec2.describe_security_groups(GroupIds=[group_id])['SecurityGroups'][0]
        
            # remove all inbound rules for the sg group to deny ssh and https access
            
                for permission in group['IpPermissions']:
                    ec2.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[permission]
                    )
                    print(f"Removed inbound rule {permission}")
    
            iam = boto3.client('iam')
            
            try:
                response = iam.list_groups_for_user(UserName=user_name)
                group_name = response['Groups'][0]['GroupName']
                response = iam.remove_user_from_group(
                    GroupName=group_name,
                    UserName=user_name
                    )
                print("User is removed from IAM group:", group_name)
                
            except IndexError as f:
                print(f)
            
            attached_policies = iam.list_attached_user_policies(UserName=user_name)
            # Detach all the policies
            for policy in attached_policies['AttachedPolicies']:
                policy_arn = policy['PolicyArn']
                iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            
            print("All attached policies are removed from user...")
            # Get a list of the user's inline policies        
            user_policies = iam.list_user_policies(UserName=user_name)
            
            # Delete all the inline policies
            for policy in user_policies['PolicyNames']:
                iam.delete_user_policy(UserName=user_name, PolicyName=policy)
            
            print("All inline policies are removed from user......")
            
            iam.delete_login_profile(UserName=user_name)
            
            print("login profile deleted")
            
            access_keys = iam.list_access_keys(UserName=user_name)
            
            # Delete all the access keys
            for access_key in access_keys['AccessKeyMetadata']:
                access_key_id = access_key['AccessKeyId']
                iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            
            print("All access keys are removed from user......")
            iam.delete_user(UserName=user_name)
            print("IAM user has been deleted and logged out of AWS..")
            
            
            
            sns = boto3.client('sns')
            topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-user-access-revoke'
            message = f"Hi Admin \n\n Part of hiring infra setup the lambda function Hiring-User-Access-Revoke has been invoked.\n All exsiting permissions of the user are deleted.\nThe IAM user: [{user_name}] has also been deleted.The user will no longer have access to the AWS account"
            sns.publish(TopicArn=topic_arn, Message=message)
        
        except ClientError as e:
            #print(e)
            sns = boto3.client('sns')
            topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-user-access-revoke'
            message = f"Hi Admin \n\n Part of hiring infra setup the lambda [Hiring-User-Access-Revoke] has faced an error \n\n{e}"
            sns.publish(TopicArn=topic_arn, Message=message)
              
    
    
    
    
    

    
    