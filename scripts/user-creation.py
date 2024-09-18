import json      
import pyzipper  
import io
import os
import boto3
import secrets     
import string
import random
import urllib.parse
import datetime
from botocore.exceptions import ClientError


s3 = boto3.client("s3")     
ec2=boto3.client("ec2", region_name="us-east-2")
iam_client =boto3.client("iam")
iam = boto3.client('iam')

S3_BUCKET = 'hiring-userdata-details'
PASSWORD_LENGTH = 12
vpc_id = 'vpc-0228a187b275374ff'        
rg = 'us-east-2'        

def lambda_handler(event, context):  
    object_key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
    file_content = s3.get_object(Bucket=S3_BUCKET, Key=object_key)["Body"].read().decode('UTF-8')
    # Check if the object key has the specified prefix and suffix
    if object_key.startswith('Candidate-details/') and object_key.endswith('.txt'):
        
        obj_name = os.path.basename(object_key)
        obj = obj_name[:-4] 

        print("File name:", obj_name)
        
        print("*******START -> FILE CONTENT***")
        print(file_content)
        print("*******END -> File CONTENT*****")
    else:
        print(f"Object with key {object_key} does not match the prefix and suffix filter")
        
    values = file_content.strip().split(",")
    if len(values) == 3:
        email, ip_adr,lab_num = values
    else:
        # Handle the case where there are not exactly three values
        print(f"Unexpected number of values in file content: {len(values)}")
        bucket_name="hiring-userdata-details"
        file_name = "AWS-credentials/"+ obj + "-invalid-input.txt"
        Body = f"The file content is not as expected.The input file should be of 3 values but the\n file content is: {file_content}"
        s3.put_object(Bucket=bucket_name, Key=file_name, Body=Body)
        
    email, ip_adr ,lab_num = file_content.strip().split(",")
    sg_ip = ip_adr[ip_adr.find('[') + 1 : ip_adr.find(']')] + '/32'

    
    try:
        # Check if security group already exists
        security_groups = ec2.describe_security_groups(Filters=[
        {'Name': 'group-name', 'Values': [email + '-SG1']}
        ])['SecurityGroups']
    
        if security_groups:
        # Security group already exists, check ingress rules
            security_group_id = security_groups[0]['GroupId']
            ip_permissions = security_groups[0]['IpPermissions']
            print('Security group %s already exists')
        
        # Check if ingress rules already exist
            existing_rules = [(p['IpProtocol'], p['FromPort'], p['ToPort'], r['CidrIp'])
                                for p in ip_permissions for r in p['IpRanges']]
        
            if ('tcp', 80, 80, sg_ip) not in existing_rules:
                # HTTP ingress rule not present, add it
                ec2.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': sg_ip}]
                    }]
                )
                print('HTTP ingress rule added to security group %s' % security_group_id)
        
            if ('tcp', 22, 22, sg_ip) not in existing_rules:
                # SSH ingress rule not present, add it
                ec2.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': sg_ip}]
                    }]
                )
                print('SSH ingress rule added to security group %s' % security_group_id)
            
            if ('tcp', 80, 80, security_group_id) not in existing_rules:
                #self sg rule for port 80
                ec2.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'UserIdGroupPairs': [{'GroupId': security_group_id}]
                    }]
                )
                print('Self SSH ingress rule added to security group %s' % security_group_id)
            
        
        # Ingress rules already present, no need to do anything
            print('Security group %s already exists, ingress rules are up-to-date' % security_group_id)
    
        else:
            # Security group does not exist, create it and add ingress rules
            response = ec2.create_security_group(
                GroupName=email + '-SG1',
                Description='Security groupG FOR Candidate',
        
                VpcId=vpc_id
            )
            security_group_id = response['GroupId']
            
            ec2.create_tags(
                Resources=[security_group_id],
                Tags=[{'Key': 'Owner', 'Value': email}]
            )
            print('Security Group Created and Tagged %s in vpc %s.' % (security_group_id, vpc_id))

        # Add HTTP and SSH ingress rules
            ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': sg_ip}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': sg_ip}]
                    },
                    {
                        'IpProtocol' : 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'UserIdGroupPairs': [{'GroupId': security_group_id}]
                        
                    }
                ]
            )
            print('Ingress rules added to security group %s' % security_group_id)

    except ClientError as e:
        print(e)
 # create an acl based on the public ip retrieved
    def generate_password():
        """Generate a random password."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for i in range(PASSWORD_LENGTH))
        
    try:
    # Check if user already exists
        existing_user = iam_client.get_user(UserName=email)

    # User already exists, skip creating new user and login profile
        print('User %s already exists' % email)
        
        bucket_name="hiring-userdata-details"
        file_name = "AWS-credentials/"+ obj + "-output(user-exists).txt"
        Body = f"IAM User Name: {email}\nuser already exists in AWS.\npublic IP has been updated in AWS\nsecurity_group:{security_group_id}\n\nSecurityGroupname:{email+'-SG1'}\nPlease use the above security group for AWS usage for all activities\nPlease use the below link for login to the AWS: \nhttps://167854621873.signin.aws.amazon.com/console\n The access will only be valid for 3 hours after creation of this file"
        s3.put_object(Bucket=bucket_name, Key=file_name, Body=Body)
        
        print("The credentials are uploaded to s3 successfully........")  

    except iam_client.exceptions.NoSuchEntityException as e:
    
        
        try:
        
            response = iam_client.create_user(UserName=email)
            user_name = response['User']['UserName']
            print('User Created %s' % user_name)
    
            password = generate_password()
    
            iam_client.create_login_profile(
                UserName=user_name,
                Password=password,
                PasswordResetRequired=True                          
                )
            print('Password set for user %s' % password)
            
            # need to make change here for group allocation
            if lab_num == 'lab1':
                iam_group_name = 'Hiring-lab-assignment-1'
                iam.add_user_to_group(GroupName=iam_group_name, UserName=email)
                print('User  Attached to group: %s' %iam_group_name )
                
            if lab_num == 'lab2':
                iam_group_name = 'Hiring-lab-assignment-2'
                iam.add_user_to_group(GroupName=iam_group_name, UserName=email)
                print('User  Attached to group: %s' %iam_group_name )
            else:
                print("invalid lab val")
                # Add the user to the group
           
#use this block if creds are required
            # Create access keys and secret keys for the user
            #access_key = iam.create_access_key(UserName=email)
            #print('Access Key: %s' % access_key['AccessKey']['AccessKeyId'])
            #print('Secret Key: %s' % access_key['AccessKey']['SecretAccessKey'])
            # below line to be added to s3 message
            #Access Key ID: {access_key['AccessKey']['AccessKeyId']}\nSecret Access Key: {access_key['AccessKey']['SecretAccessKey']}\n
            
        except Exception as e:
            print('Error:', e)
            sns = boto3.client('sns')
            topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-user-creation-sns'
            message = f"Hi Admin \n\n Part of hiring infra setup the lambda function Hiring-User-Creation has been invoked as result of candidate detail upload at :\n{object_key} in the S3 bucket {S3_BUCKET}.\n The below error has raised : {e}"
            sns.publish(TopicArn=topic_arn, Message=message)
        
   
    bucket_name="hiring-userdata-details"            
    file_name = "AWS-credentials/"+ obj + "-output.zip"
    
    password_bytes = b"Hire@123"      
    zip_password = "Hire@123"
    
    Body = f"IAM User Name: {user_name}\nPassword: {password}\nregion to be used for assignment : {rg}\nVPC to be used : {vpc_id}\nSecurityGroupname:{email+'-SG1'}\nsecurity_group:{security_group_id}\nPlease use the above security group for AWS usage for all activities\n\nPlease use the below link for login to the AWS: \nhttps://167854621873.signin.aws.amazon.com/console\n The access will only be valid for 3 hours after creation of this file"
    
    

    # Compress the file and encrypt it with a password
    zip_data = io.BytesIO()
    with pyzipper.AESZipFile(zip_data, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_file:
        # Set the password for the zip file
        zip_file.setpassword(password_bytes)     
    
        # Add the file to the zip file
        zip_file.writestr('output.txt', Body)     

    # Get the encrypted data as bytes
    encrypted_zip_data = zip_data.getvalue()
    
    # Upload the encrypted file to Amazon S3
    s3.put_object(Body=encrypted_zip_data, Bucket=bucket_name, Key=file_name)                 
    
    print("The credentials are uploaded to s3 successfully........")  
    
    try:
        now = datetime.datetime.now()   ## current time
        date = datetime.date.today()
    
        start_time = now + datetime.timedelta(minutes=10)       ## access revocation
        start_time_ist = datetime.timedelta(hours=5, minutes=30) + start_time
        
        start_time_two = now + datetime.timedelta(minutes=20)      ## resource termination     
        start_time_two_ist = datetime.timedelta(hours=5, minutes=30) +start_time_two
        
        start_time_three = now + datetime.timedelta(minutes=15)     ## logs upload
        start_time_three_ist = datetime.timedelta(hours=5, minutes=30) +start_time_three
        
        start_time_four = now + datetime.timedelta(minutes=25)     ## recheck for any non deleted resources
        start_time_four_ist = datetime.timedelta(hours=5, minutes=30) +start_time_four
        
        start_time_five = now + datetime.timedelta(minutes=11)     ## recheck for any non deleted resources
        start_time_five_ist = datetime.timedelta(hours=5, minutes=30) +start_time_five
        
        
#1. Create a CloudWatch Events rule to trigger the access revocation Lambda function.....
        events_client = boto3.client('events')
        rule_name = f'Hiring-user-Access-Revoke-Rule-{user_name.split("@")[0]}'
        
        schedule_expression = f'cron({start_time.minute} {start_time.hour} {start_time.day} {start_time.month} ? {start_time.year})'
        
        response = events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Tags=[
            {'Key': 'Owner', 'Value': user_name},
        ]
        )
        
        print(f'CW event rule created {rule_name} ..............')
        
        # Assign the access revocation Lambda function as the target for the CloudWatch Events rule
        lambda_client= boto3.client('lambda')
        target_function_arn = 'arn:aws:lambda:us-east-1:167854621873:function:Hiring-User-Access-Revoke'
        
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'Hiring-User-Access-Revoke',
                    'Arn': target_function_arn,
                    'Input': json.dumps({
                        'user_name': user_name
                    })
                }
            ]
        )
        
        print("CW event targets are assigned with payload............")
        
        function_name = 'Hiring-User-Access-Revoke'
        Rule_name = rule_name
    
        response = events_client.describe_rule(Name=rule_name)
        event_arn = response['Arn']
    
        # Add the event rule as a trigger to the Lambda function
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId= rule_name + "--"+ str(date),   
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=event_arn
        )
        
        print(" lambda trigger has been updated ...........")
    
        print(f'Access revocation scheduled for {user_name} at {start_time_ist}')
        
#2. Create a second CloudWatch Events rule to trigger the resource termination Lambda function
        
        events_client = boto3.client('events')
        rule_name = f'Hiring-Resource-Termination-Rule-{user_name.split("@")[0]}'
        schedule_expression = f'cron({start_time_two.minute} {start_time_two.hour} {start_time_two.day} {start_time_two.month} ? {start_time_two.year})'
        
        response = events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Tags=[
            {'Key': 'Owner', 'Value': user_name},
        ]
        )
        
        print(f'Second CW event rule created {rule_name} ..............')
        
        # Assign the resource termination Lambda function as the target for the CloudWatch Events rule
        lambda_client= boto3.client('lambda')
        target_function_arn = 'arn:aws:lambda:us-east-1:167854621873:function:Hiring-Resource-Termination'
        
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'Hiring-Resource-Termination',
                    'Arn': target_function_arn,
                    'Input': json.dumps({
                        'user_name': user_name
                    })
                }
            ]
        )
        
        print("Second CW event targets are assigned with payload........")
        
        function = 'Hiring-Resource-Termination'
        Rule = rule_name
    
        response = events_client.describe_rule(Name=rule_name)
        event_arn = response['Arn']
    
        # Add the event rule as a trigger to the Lambda function
        lambda_client.add_permission(
            FunctionName=function,
            StatementId= rule_name+ "--" + str(date),   
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=event_arn
        )
        
        print(" Second lambda trigger has been updated ...............")
    
        print(f'Resource termination scheduled for {user_name} at {start_time_two_ist}')
        
        
#5. Create a fifth CloudWatch Events rule to trigger the Hiring-Ec2-autostop Lambda function
        
        events_client = boto3.client('events')
        rule_name = f'Hiring-Ec2-autostop-Rule-{user_name.split("@")[0]}'
        schedule_expression = f'cron({start_time_five.minute} {start_time_five.hour} {start_time_five.day} {start_time_five.month} ? {start_time_five.year})'
        
        response = events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Tags=[
            {'Key': 'Owner', 'Value': user_name},
        ]
        )
        
        print(f'Fifth CW event rule created {rule_name} ..............')
        
        # Assign the resource termination Lambda function as the target for the CloudWatch Events rule
        lambda_client= boto3.client('lambda')
        target_function_arn = 'arn:aws:lambda:us-east-1:167854621873:function:Hiring-Ec2-autostop'
        
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'Hiring-Ec2-autostop',
                    'Arn': target_function_arn,
                    'Input': json.dumps({
                        'user_name': user_name
                    })
                }
            ]
        )
        
        print("fifth CW event targets are assigned with payload........")
        
        function = 'Hiring-Ec2-autostop'
        Rule = rule_name
    
        response = events_client.describe_rule(Name=rule_name)
        event_arn = response['Arn']
    
        # Add the event rule as a trigger to the Lambda function
        lambda_client.add_permission(
            FunctionName=function,
            StatementId= rule_name+ "--" + str(date),   
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=event_arn
        )
        
        print(" fifth lambda trigger has been updated ...............")
    
        print(f'EC2 instance stoppage is scheduled for {user_name} at {start_time_five_ist}')
        
        
        
#4. Create a 4th CloudWatch Events rule to trigger the resource termination Lambda function 2nd time.....
        
        events_client = boto3.client('events')
        rule_name = f'Hiring-Resource-Termination-Rule-2-{user_name.split("@")[0]}'
        schedule_expression = f'cron({start_time_four.minute} {start_time_four.hour} {start_time_four.day} {start_time_four.month} ? {start_time_four.year})'
        
        response = events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Tags=[
            {'Key': 'Owner', 'Value': user_name},
        ]
        )
        
        print(f'fourth CW event rule created {rule_name} ..............')
        
        # Assign the resource termination Lambda function as the target for the CloudWatch Events rule
        lambda_client= boto3.client('lambda')
        target_function_arn = 'arn:aws:lambda:us-east-1:167854621873:function:Hiring-Resource-Termination'
        
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'Hiring-Resource-Termination',
                    'Arn': target_function_arn,
                    'Input': json.dumps({
                        'user_name': user_name
                    })
                }
            ]
        )
        
        print("fourth CW event targets are assigned with payload........")
        
        function = 'Hiring-Resource-Termination'
        Rule = rule_name
    
        response = events_client.describe_rule(Name=rule_name)
        event_arn = response['Arn']
    
        # Add the event rule as a trigger to the Lambda function
        lambda_client.add_permission(
            FunctionName=function,
            StatementId= rule_name+ "--" + str(date),   
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=event_arn
        )
        
        print(" fourth lambda trigger has been updated ...............")
    
        print(f'Secondary Resource termination scheduled for {user_name} at {start_time_four_ist}')
   
#3. Create a third CloudWatch Events rule to trigger the log monitor file upload
        
        events_client = boto3.client('events')
        rule_name = f'Hiring-Userlogs-Monitor-Rule-{user_name.split("@")[0]}'
        schedule_expression = f'cron({start_time_three.minute} {start_time_three.hour} {start_time_three.day} {start_time_three.month} ? {start_time_three.year})'
        
        response = events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Tags=[
            {'Key': 'Owner', 'Value': user_name},
        ]
        )
        
        print(f'Third CW event rule created {rule_name} ..............')
        
        # Assign the log monitor Lambda function as the target for the CloudWatch Events rule
        lambda_client= boto3.client('lambda')
        target_function_arn = 'arn:aws:lambda:us-east-1:167854621873:function:Hiring-Userlogs-Monitor'
        
        events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'Hiring-Userlogs-Monitor',
                    'Arn': target_function_arn,
                    'Input': json.dumps({
                        'user_name': user_name
                    })
                }
            ]
        )
        
        print("Third CW event targets are assigned with payload........")
        
        function = 'Hiring-Userlogs-Monitor'
        Rule = rule_name
    
        response = events_client.describe_rule(Name=rule_name)
        event_arn = response['Arn']
    
        # Add the event rule as a trigger to the Lambda function
        lambda_client.add_permission(
            FunctionName=function,
            StatementId= rule_name+ "--" + str(date),   
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=event_arn
        )
        
        print(" Third lambda trigger has been updated ...............")
    
        print(f'Log data upload scheduled for {user_name} at {start_time_three_ist} to S3 bucket hiring-userlogs')         
        
    except Exception as e:
            print('Error:', e)
            sns = boto3.client('sns')
            topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-user-creation-sns'     
            message = f"Hi Admin \n\n Part of hiring infra setup the lambda function Hiring-User-Creation has been invoked as result of candidate detail upload at :\n{object_key} in the S3 bucket {S3_BUCKET}.\n The below error has raised : {e}"      
            sns.publish(TopicArn=topic_arn, Message=message)
        
    sns = boto3.client('sns')
    topic_arn = 'arn:aws:sns:us-east-1:167854621873:Hiring-user-creation-sns'
    message = f"Hi Admin \n\n Part of hiring infra setup the lambda function Hiring-User-Creation has been invoked as result of candidate detail upload at :\n{object_key} in the S3 bucket {bucket_name}.\nAWS account access has been created for the IAM user: {user_name} with required permissions part of lab assignement: {lab_num}.\nThe password for the zipped file is :: {zip_password}\n\nThe IAM access revoke is scheduled at : [{start_time_ist}].\nThe EC2 instance autostop is scheduled at [{start_time_five_ist}].\nThe user Log data upload is scheduled at [{start_time_three_ist}] \nThe resource termination scheduled at : [{start_time_two_ist}] \nThe secondary resource termination scheduled at : [{start_time_four_ist}]"
    sns.publish(TopicArn=topic_arn, Message=message)         
    
    
               
      