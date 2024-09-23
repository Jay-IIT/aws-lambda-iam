import os
import snowflake.connector
import boto3
import logging
from datetime import datetime, timedelta, date
import json
import base64
from botocore.exceptions import BotoCoreError, NoCredentialsError, ClientError
 
# Set up logging to output to CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

if logger.hasHandlers():
    logger.handlers.clear()

console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Initialize AWS clients
iam_client = boto3.client('iam')
lambda_client = boto3.client('lambda')

# Configuration for thresholds
KEY_EXPIRATION_THRESHOLD = int(os.getenv("KEY_EXPIRATION_THRESHOLD", "83"))
REMINDER_PERIOD_THRESHOLD = int(os.getenv("REMINDER_PERIOD_THRESHOLD", "1"))
TIME_UNIT = os.getenv("TIME_UNIT", "days")
GRACE_PERIOD_THRESHOLD = int(os.getenv("GRACE_PERIOD_THRESHOLD", "7"))

# Default 'from' email address
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@biopharmdatasupport.com")

# Helper function to convert time threshold into timedelta
def get_time_threshold(time_threshold):
    if TIME_UNIT == "days":
        return timedelta(days=time_threshold)
    elif TIME_UNIT == "hours":
        return timedelta(hours=time_threshold)
    elif TIME_UNIT == "minutes":
        return timedelta(minutes=time_threshold)
    elif TIME_UNIT == "seconds":
        return timedelta(seconds=time_threshold)
    else:
        logger.warning(f"Invalid TIME_UNIT '{TIME_UNIT}', defaulting to days.")
        return timedelta(days=time_threshold)

# Fetch Snowflake connection config from environment variables
def get_snowflake_config():
    return {
        'user': os.getenv('SNOWFLAKE_USER'),
        'password': os.getenv('SNOWFLAKE_PASSWORD'),
        'account': os.getenv('SNOWFLAKE_ACCOUNT'),
        'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
        'database': os.getenv('SNOWFLAKE_DATABASE'),
        'schema': os.getenv('SNOWFLAKE_SCHEMA'),
        'tablename': os.getenv('SNOWFLAKE_TABLENAME')
    }

# Create Snowflake connection
def get_snowflake_connection():
    try:
        config = get_snowflake_config()
        logger.info("Attempting to connect to Snowflake...")
        connection = snowflake.connector.connect(
            user=config['user'],
            password=config['password'],
            account=config['account'],
            warehouse=config['warehouse'],
            database=config['database'],
            schema=config['schema']
        )
        logger.info("Connected to Snowflake successfully.")
        return connection
    except Exception as e:
        logger.error(f"Error connecting to Snowflake: {str(e)}")
        return None

# Base64 Encode data
def base64_encode(data):
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encoding data: {str(e)}")
        return None

# Base64 Decode data
def base64_decode(data):
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        logger.error(f"Error decoding data: {str(e)}")
        return None

      # Retrieve access key creation dates from IAM and log the age of the keys
def get_access_key_creation_date_from_iam(username):
    try:
        logger.info(f"Retrieving access keys for user {username} from IAM...")
        keys_response = iam_client.list_access_keys(UserName=username)
        access_keys = keys_response.get('AccessKeyMetadata', [])
        
        key_creation_dates = []
        expiration_threshold = get_time_threshold(KEY_EXPIRATION_THRESHOLD)  # Expiration threshold
        grace_period_threshold = get_time_threshold(GRACE_PERIOD_THRESHOLD)  # Grace period threshold
        final_reminder_threshold = get_time_threshold(REMINDER_PERIOD_THRESHOLD)
        now = datetime.now()

        for key in access_keys:
            creation_date = key['CreateDate'].replace(tzinfo=None)  # Remove timezone info
            key_age = now - creation_date  # Calculate key age using timedelta

            logger.info(f"Key {key['AccessKeyId']} for user {username} is {key_age.total_seconds()} seconds old.")
            
            if key_age > expiration_threshold + grace_period_threshold:
                status = 'expired'
            elif key_age > expiration_threshold:
                status = 'about_to_expire'
            else:
                status = 'active'
            send_final_reminder = False
            final_reminder_threshold = expiration_threshold + grace_period_threshold - final_reminder_threshold
            if final_reminder_threshold <= key_age <= expiration_threshold + grace_period_threshold:
                send_final_reminder = True
 
             
              
            key_creation_dates.append({
                'AccessKeyId': key['AccessKeyId'],
                'CreateDate': creation_date,
                'KeyAge': key_age,
                'Status': status,
                'FinalReminder':send_final_reminder
            })
        
        return key_creation_dates
    except Exception as e:
        logger.error(f"Error retrieving keys from IAM for user {username}: {str(e)}")
        return []

# Generate new AWS access key
def generate_new_aws_access_key(username):
    try:
        logger.info(f"Generating new AWS access key for user {username}...")
        response = iam_client.create_access_key(UserName=username)
        access_key = response.get('AccessKey', {})
        logger.info(f"Access key generated successfully for {username} \n Access Key {access_key['AccessKeyId']} \n Secret Key  {access_key['SecretAccessKey']}.")
        return access_key['AccessKeyId'], access_key['SecretAccessKey']
    except (BotoCoreError, NoCredentialsError, ClientError) as e:
        logger.error(f"Error generating access key for {username}: {str(e)}")
        return None, None
      
def deactivate_old_aws_access_keys(username, access_key_ids, key_creation_dates):
    expiration_threshold = get_time_threshold(KEY_EXPIRATION_THRESHOLD)
    grace_period = get_time_threshold(GRACE_PERIOD_THRESHOLD)
    now = datetime.now()

    try:
        for access_key_id, creation_date in zip(access_key_ids, key_creation_dates):
            key_age = now - creation_date

            if key_age > expiration_threshold:
                if key_age > (expiration_threshold + grace_period):
                    iam_client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status='Inactive')
                    logger.info(f"Deactivated access key {access_key_id} for {username}.")
                    iam_client.delete_access_key(UserName=username, AccessKeyId=access_key_id)
                    logger.info(f"Deleted access key {access_key_id} for {username}.")
                else:
                    logger.info(f"Access key {access_key_id} for {username} is marked as about_to_expire and within the grace period.")
            else:
                logger.info(f"Access key {access_key_id} for {username} is still within the valid period.")
    except Exception as e:
        logger.error(f"Error deactivating or deleting access key {access_key_id} for {username}: {str(e)}")
# Fetch the stored keys from Snowflake table for a user
def get_stored_keys(conn, username):
    if conn:
        try:
            cur = conn.cursor()
            logger.info(f"Fetching keys and metadata for user {username}...")
            query = f"""
                SELECT ACCESS_KEY, SECRET_KEY, LASTKEYGENERATEDDATE, SKIP_KEY_ROTATION
                FROM {get_snowflake_config()['tablename']}
                WHERE USERNAME = %s
            """
            cur.execute(query, (username,))
            result = cur.fetchone()

            if result:
                access_key, secret_key, last_key_generated_date, skip_rotation = result
                return {
                    "access_key": base64_decode(access_key),
                    "secret_key": base64_decode(secret_key),
                    "last_key_generated_date": last_key_generated_date.strftime('%Y-%m-%d') 
                                               if isinstance(last_key_generated_date, date) else str(last_key_generated_date),
                    "skip_rotation": skip_rotation
                }
            else:
                logger.warning(f"No keys found for user {username}.")
                return None
        except Exception as e:
            logger.error(f"Error fetching keys for user {username}: {str(e)}")
            return None

# Store keys in Snowflake (Base64 encoded)
def store_keys_in_snowflake(conn, username, access_key, secret_key):
    if conn:
        try:
            cur = conn.cursor()
            logger.info(f"Storing Base64-encoded keys for user {username}...")
            today_date = datetime.today().strftime('%Y-%m-%d')
            query = f"""
                UPDATE {get_snowflake_config()['tablename']}
                SET ACCESS_KEY = %s, SECRET_KEY = %s, LASTKEYGENERATEDDATE = %s
                WHERE USERNAME = %s
            """
            cur.execute(query, (
                base64_encode(access_key), 
                base64_encode(secret_key), 
                today_date, 
                username
            ))
            conn.commit()
            logger.info(f"Keys and LastKeyGeneratedDate stored successfully for user {username}.")
        except Exception as e:
            logger.error(f"Error storing keys for user {username}: {str(e)}")


def extract_name_from_email(email):
    # Split the email at '@', then split the part before '@' by '.'
    name_part = email.split('@')[0]
    name_parts = name_part.split('.')
    
    # If both first and last names are present, capitalize them
    if len(name_parts) >= 2:
        first_name = name_parts[0].capitalize()
        last_name = name_parts[1].capitalize()
        return f"{first_name} {last_name}"
    else:
        # If we can't find both first and last names, return the email as a fallback
        return name_part


# Function to format the email body
def format_email_body(to_emails, old_access_key, new_access_key, secret_access_key, is_final_notice):
    # Extract names from emails
    to_emails = to_emails.split(",")
    recipient_names = [extract_name_from_email(email) for email in to_emails]
    joined_names = ", ".join(recipient_names)

    # Build the email body
    email_body = f"""
    <html>
    		 <head>
                <style>
                    .code-block {{
                        background-color: #f5f5f5;
                        border: 1px solid #e0e0e0;
                        padding: 10px;
                        font-family: monospace;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        border-radius: 5px;
                        margin: 10px 0;
                    }}
                    .copy-btn {{
                        background-color: #007bff;
                        color: white;
                        border: none;
                        cursor: pointer;
                        padding: 5px 10px;
                        border-radius: 3px;
                        font-size: 12px;
                    }}
                </style>
            </head>
        <body>
            <p>Dear {joined_names},</p>
            <p>As per the AWS IAM Keys Rotation notification email sent to you earlier, we have created a new set of Access Keys (Access Keys and Secret Access Keys) for your Account.</p>
            <p>For your reference, please see below the old Access key which you are presently using:</p>
             <p><strong>Old Access Key:</strong></p>
            <div class="code-block">{old_access_key}</div>
            <p>Should be replaced with the new Access key and Secret Access Key provided below:</p>
                <p><strong>New Access Key:</strong></p>
                <div class="code-block">{new_access_key}</div>

                <p><strong>Secret Access Key:</strong></p>
                <div class="code-block">{secret_access_key}</div>
                
            <p>Please note that you must change your keys immediately in all locations as soon as possible.</p>
            <p>Your old keys will still be active for another 7 days, after which they will be deleted.</p>
            <p>Note that your present access to AWS resources, including S3 buckets, will not be affected by this change.</p>
            <p>Most importantly, do not expose your Secret Access Keys in any media such as Emails, Support Tickets, etc.</p>
            {'<p>This is your final notice.</p>' if is_final_notice else ''}
            <p>This is an automated message, please do not reply. If you have any queries, please write to data@biopharmcommunications.com.</p>
            <p>Best Regards,<br>BioPharm Data Support</p>
        </body>
    </html>
    """
    return email_body

# Main function to send the email
def send_email(to_emails, cc_point_of_contacts, old_access_key, new_access_key, secret_access_key,
               is_final_notice=False, key_expiration_date="2024-12-31",
               subject="BioPharm AWS 90 Day Access Key Rotation Notification"):
    try:
        # Call the email body formatting function
        email_body = format_email_body(to_emails, old_access_key, new_access_key, secret_access_key, is_final_notice)

        # Construct the event data payload
        event_data = {
            "body": json.dumps({
                "data": [
                    [0,
                     to_emails,  # To emails as comma-separated
                     "no-reply@biopharmdatasupport.com",  # From email
                     subject,  # Subject
                     email_body,  # HTML body
                    cc_point_of_contacts  # CC emails
                    ]
                ]
            })
        }

        # Log the payload
        logging.info(f"Invoking email Lambda with payload: {json.dumps(event_data, indent=2)}")

        # Invoke the Lambda function
        response = lambda_client.invoke(
            FunctionName='email',  # Replace with your Lambda function name
            InvocationType='RequestResponse',  # Wait for the Lambda function to return
            Payload=json.dumps(event_data)  # Send the payload as JSON
        )

        # Get and log the response
        response_payload = json.loads(response['Payload'].read().decode("utf-8"))
        logging.info(f"Lambda response: {json.dumps(response_payload, indent=2)}")
        return response_payload
    except Exception as e:
        logging.error(f"Error While Sending email: {str(e)}")


 

def rotate_keys_for_users(conn):
    if conn:
        try:
            cur = conn.cursor()
            logger.info("Fetching users from Snowflake for key rotation...")
            query = f"""
                SELECT USERNAME, TO_POINTOFCONTACTS, CC_POINTOFCONTACTS
                FROM {get_snowflake_config()['tablename']}
                WHERE SKIP_KEY_ROTATION = 'N'
            """
            cur.execute(query)
            users = cur.fetchall()

            for user in users:
                username = user[0]
                to_point_of_contacts = user[1]
                cc_point_of_contacts = user[2]
                logger.info(f"Processing key rotation for user: {username}")

                # Fetch access key data from IAM
                access_key_data = get_access_key_creation_date_from_iam(username)

                if len(access_key_data) == 0:
                    # No keys found: create a new one
                    #key_id = access_key_data[-1]['AccessKeyId']
                    logger.info(f"No keys found for user {username}, creating a new key.")
                    access_key, secret_key = generate_new_aws_access_key(username)
                    if access_key and secret_key:
                        store_keys_in_snowflake(conn, username, access_key, secret_key)
                        send_email(
                            to_point_of_contacts, cc_point_of_contacts,"N/A", access_key, secret_key,
                            is_final_notice=False, key_expiration_date="N/A",
                            subject="BioPharm AWS Key Rotation - New Access Key Generated"
                        )

                elif len(access_key_data) == 1:
                    # Handle a single key (active, about to expire, or expired)
                    key_id = access_key_data[0]['AccessKeyId']
                    key_status = access_key_data[0]['Status']
                    create_date = access_key_data[0]['CreateDate']
                    final_reminder = access_key_data[0]['FinalReminder']
				    if final_reminder:
                        send_email(to_point_of_contacts, cc_point_of_contacts, key_id, key_id, "secret_key",
                                   is_final_notice=True, key_expiration_date=None,
                                   subject="BioPharm AWS Key Rotation - Final Notice")
                      
                    if key_status == 'expired':
                        # Key is expired: create new, deactivate the old one
                        logger.info(f"Key expired for user {username}. Rotating keys.")
                        access_key, secret_key = generate_new_aws_access_key(username)
                        if access_key and secret_key:
                            store_keys_in_snowflake(conn, username, access_key, secret_key)
                            deactivate_old_aws_access_keys(username, [key_id], [create_date])
                            send_email(
                                to_point_of_contacts, cc_point_of_contacts, key_id, access_key, secret_key,
                                is_final_notice=False, key_expiration_date=None,
                                subject="BioPharm AWS Key Rotation - New Access Key Generated")

                    elif key_status == 'about_to_expire':
                        # Key is about to expire: create new key but don’t delete the old one yet
                        logger.info(f"Key for user {username} is about to expire. Creating a new key.")
                        access_key, secret_key = generate_new_aws_access_key(username)
                        if access_key and secret_key:
                            store_keys_in_snowflake(conn, username, access_key, secret_key)
                            send_email(
                                to_point_of_contacts, cc_point_of_contacts, key_id, access_key, secret_key,
                                is_final_notice=False, key_expiration_date=None,
                                subject="BioPharm AWS Key Rotation - New Access Key Generated")
                    elif key_status == 'active':
                        logger.info(f"Key for user {username} is still active, no action required.")

                elif len(access_key_data) == 2:
                    # Handle two keys
                    expired_keys = [key for key in access_key_data if key['Status'] == 'expired']
                    about_to_expire_keys = [key for key in access_key_data if key['Status'] == 'about_to_expire']
					final_reminder = any(key['FinalReminder'] for key in access_key_data)
					if final_reminder:
                        send_email(to_point_of_contacts, cc_point_of_contacts, key_id, key_id, "secret_key",
                                is_final_notice=True, key_expiration_date=None,
                                subject="BioPharm AWS Key Rotation - Final Notice")
                    if len(expired_keys) == 2:
                        # Both keys expired: delete both and create a new key
                        logger.info(f"Both keys expired for user {username}. Deleting both and creating a new key.")
                        deactivate_old_aws_access_keys(username, [key['AccessKeyId'] for key in expired_keys], [key['CreateDate'] for key in expired_keys])
                        access_key, secret_key = generate_new_aws_access_key(username)
                        if access_key and secret_key:
                            store_keys_in_snowflake(conn, username, access_key, secret_key)
                            send_email(
                                to_point_of_contacts, cc_point_of_contacts, expired_keys[-1]['AccessKeyId'], access_key, secret_key,
                                is_final_notice=False, key_expiration_date=None,
                                subject="BioPharm AWS Key Rotation - New Access Key Generated"
                            )

                    elif len(expired_keys) == 1:
                        # One key expired: delete it and create a new one
                        logger.info(f"One key expired for user {username}. Deleting expired key and creating a new key.")
                        deactivate_old_aws_access_keys(username, [expired_keys[0]['AccessKeyId']], [expired_keys[0]['CreateDate']])

            conn.commit()
            logger.info("Key rotation process completed.")

        except Exception as e:
            logger.error(f"Error rotating keys for users: {str(e)}")


def lambda_handler(event, context):
    conn = None
    try:
        # Establish the Snowflake connection
        conn = get_snowflake_connection()
        
        action = event.get('action')
        if action == 'getkeys':
            username = event.get('username')
            if not username:
                return {'statusCode': 400, 'body': 'Username not provided'}
            
            keys = get_stored_keys(conn,username)
            if keys:
                return {'statusCode': 200, 'body': json.dumps(keys)}
            else:
                return {'statusCode': 404, 'body': 'No keys found for the specified user'}
        else:
            rotate_keys_for_users(conn)
            return {'statusCode': 200, 'body': 'Key rotation and deactivation completed successfully'}
    except Exception as e:
        logger.error(f"Error in Lambda function: {str(e)}")
        return {'statusCode': 500, 'body': 'An error occurred'}
    finally:
        # Close the Snowflake connection at the end
        if conn:
            conn.close()
            logger.info("Snowflake connection closed.")
