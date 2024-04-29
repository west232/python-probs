import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Function to check the last used date of an IAM user's access key
def check_access_key_last_used(iam_client, username):
    try:
        access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for access_key in access_keys:
            access_key_last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
            if 'LastUsedDate' in access_key_last_used:
                last_used_date = access_key_last_used['AccessKeyLastUsed']['LastUsedDate'].replace(tzinfo=None)
                return last_used_date
        return None
    except ClientError as e:
        print(f"Error checking access key last used for user {username}: {e}")
        return None

# Function to check the last login date of an IAM user in the AWS Management Console
def check_console_last_login(iam_client, username):
    try:
        user_details = iam_client.get_user(UserName=username)
        if 'PasswordLastUsed' in user_details['User']:
            password_last_used = user_details['User']['PasswordLastUsed'].replace(tzinfo=None)
            return password_last_used
        return None
    except ClientError as e:
        print(f"Error checking console last login for user {username}: {e}")
        return None

# Function to check the last activity of an IAM user using CloudTrail
def check_cloudtrail_last_activity(cloudtrail_client, username):
    try:
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': username}],
            StartTime=datetime.now() - timedelta(days=180),  # Search events from the last 180 days
            MaxResults=1,
            )
        if 'Events' in response and response['Events']:
            event_time = response['Events'][0]['EventTime'].replace(tzinfo=None)
            return event_time
        return None
    except ClientError as e:
        print(f"Error checking CloudTrail last activity for user {username}: {e}")
        return None

# Main function
def main():
    # Create IAM and CloudTrail clients
    iam_client = boto3.client('iam')
    cloudtrail_client = boto3.client('cloudtrail')
    result_body = ""  # Initialize result body

    try:
        # List all IAM users
        users = iam_client.list_users()['Users']
        for user in users:
            username = user['UserName']
            access_key_last_used = check_access_key_last_used(iam_client, username)
            console_last_login = check_console_last_login(iam_client, username)
            cloudtrail_last_activity = check_cloudtrail_last_activity(cloudtrail_client, username)

            # if cloudtrail_last_activity is not None:
            #     result_body += f"IAM user {username} has been active.\n"

            if access_key_last_used is  not None and console_last_login is None and cloudtrail_last_activity is None:
                # Add the user to the result body
                result_body += f"IAM user {username} has not been used (over 180 days).\n"
            else:
                # Determine the last used date among access key, console login, and CloudTrail activity
                last_used_date = max(access_key_last_used or datetime.min, 
                                     console_last_login or datetime.min, 
                                     cloudtrail_last_activity or datetime.min)
                # Calculate the number of days since the last used date
                days_since_last_used = (datetime.now() - last_used_date).days
                # If the number of days is greater than 180, add the user to the result body
                if days_since_last_used > 180:
                    result_body += f"IAM user {username} has not been used for {days_since_last_used} days.\n"

        print(result_body)
    except ClientError as e:
        print(f"Error listing IAM users: {e}")

if __name__ == "__main__":
    main()
