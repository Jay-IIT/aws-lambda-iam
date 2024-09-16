import os
import snowflake.connector
import boto3
import logging
from datetime import datetime, timedelta
import json
import base64
from botocore.exceptions import BotoCoreError, NoCredentialsError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create IAM client
iam_client = None
try:
    logger.info("Creating IAM client...")
    iam_client = boto3.client('iam')
    logger.info("IAM client created successfully.")
except (BotoCoreError, NoCredentialsError, ClientError) as e:
    logger.error(f"Error creating IAM client: {str(e)}")

# Create Lambda client
lambda_client = None
try:
    logger.info("Creating Lambda client...")
    lambda_client = boto3.client('lambda')
    logger.info("Lambda client created successfully.")
except (BotoCoreError, NoCredentialsError, ClientError) as e:
    logger.error(f"Error creating Lambda client: {str(e)}")

# Global variable to hold Snowflake connection
snowflake_conn = None

# Connect to Snowflake
def get_snowflake_connection():
    global snowflake_conn
    try:
        if snowflake_conn is None or snowflake_conn.is_closed():
            logger.info("Attempting to connect to Snowflake...")
            snowflake_conn = snowflake.connector.connect(
                user=os.getenv('SNOWFLAKE_USER'),
                password=os.getenv('SNOWFLAKE_PASSWORD'),
                account=os.getenv('SNOWFLAKE_ACCOUNT'),
                warehouse=os.getenv('SNOWFLAKE_WAREHOUSE'),
                database=os.getenv('SNOWFLAKE_DATABASE'),
                schema=os.getenv('SNOWFLAKE_SCHEMA')
            )
            logger.info("Connected to Snowflake successfully.")
        return snowflake_conn
    except Exception as e:
        logger.error(f"Error connecting to Snowflake: {str(e)}")
        snowflake_conn = None
        return None


# Encrypt data using Snowflake and convert binary result to base64 string
def encrypt_data_in_snowflake(data, secret_key):
    conn = get_snowflake_connection()
    if conn:
        try:
            cur = conn.cursor()
            query = f"SELECT ENCRYPT('{data}', 'AES', '{secret_key}')"
            cur.execute(query)
            encrypted_value_binary = cur.fetchone()[0]
            cur.close()
            
            # Convert binary to base64 string
            encrypted_value_base64 = base64.b64encode(encrypted_value_binary).decode('utf-8')
            
            return encrypted_value_base64
        except Exception as e:
            logger.error(f"Error encrypting data in Snowflake: {str(e)}")
            return None
    return None

# Decrypt base64-encoded string by converting it back to binary
def decrypt_data_in_snowflake(encrypted_data_base64, secret_key):
    conn = get_snowflake_connection()
    if conn:
        try:
            # Convert base64 string back to binary
            encrypted_value_binary = base64.b64decode(encrypted_data_base64)
            
            cur = conn.cursor()
            query = f"SELECT DECRYPT('{encrypted_value_binary.hex()}', 'AES', '{secret_key}')"
            cur.execute(query)
            decrypted_value = cur.fetchone()[0]
            cur.close()
            
            return decrypted_value
        except Exception as e:
            logger.error(f"Error decrypting data in Snowflake: {str(e)}")
            return None
    return None

# Generate new AWS access key
def generate_new_aws_access_key(username):
    if iam_client:
        try:
            logging.info(f"Creating Access Key for {username}")
            new_access_key_response = iam_client.create_access_key(UserName=username)
            new_access_key = new_access_key_response.get('AccessKey', {})
            return new_access_key['AccessKeyId'], new_access_key['SecretAccessKey']
        except Exception as e:
            logger.error(f"Error generating access key for {username}: {str(e)}")
    return None, None

# Deactivate old AWS access keys
def deactivate_old_aws_access_keys(username, last_key_generated_date, email_recipients):
    if iam_client:
        try:
            ninety_days_ago = datetime.now() - timedelta(days=90)
            if last_key_generated_date <= ninety_days_ago:
                access_keys_response = iam_client.list_access_keys(UserName=username)
                access_keys = access_keys_response.get('AccessKeyMetadata', [])
                for key in access_keys:
                    access_key_id = key['AccessKeyId']
                    key_create_date = key['CreateDate'].replace(tzinfo=None)
                    if key_create_date <= ninety_days_ago:
                        iam_client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status='Inactive')
                        logger.info(f"Deactivated access key {access_key_id} for user {username}.")
                        send_email_notification(
                            recipients=email_recipients,
                            subject="AWS Access Key Deactivation",
                            html=f"<p>Your AWS Access Key {access_key_id} has been deactivated.</p>"
                        )
        except Exception as e:
            logger.error(f"Error deactivating old access key for {username}: {str(e)}")

# Send email notification using Lambda
def send_email_notification(recipients, subject, html_content):
    if lambda_client:
        try:
            # Get the sender email from the environment variable
            from_email = os.getenv('FROM_EMAIL')

            if not from_email:
                logger.error("FROM_EMAIL environment variable is not set.")
                return

            email_lambda_payload = {
                "data": [
                    [
                        ','.join(recipients),  # Recipients as a comma-separated string
                        from_email,  # Sender email fetched from environment
                        subject,
                        html_content
                    ]
                ]
            }

            # Correctly wrap the data array inside event.body
            payload = {
                "body": json.dumps(email_lambda_payload)
            }

            response = lambda_client.invoke(
                FunctionName='email',  # Using 'email' as the function name
                InvocationType='Event',
                Payload=json.dumps(payload)
            )

            logger.info(f"Email Lambda invoked: {response}")
        except Exception as e:
            logger.error(f"Error invoking email Lambda: {str(e)}")

# Get stored keys for a user from Snowflake
def get_stored_keys(username):
    conn = get_snowflake_connection()
    if conn:
        try:
            cur = conn.cursor()
            query = f"""
                SELECT ACCESS_KEY, SECRET_KEY, LASTKEYGENERATEDDATE
                FROM KEY_ROTATION_USERS 
                WHERE USERNAME = '{username}'
            """
            cur.execute(query)
            result = cur.fetchone()
            if result:
                access_key_encrypted = result[0]
                secret_key_encrypted = result[1]
                last_generated_date = result[2]
                secret_key = 'my_secret_key'
                if access_key_encrypted and secret_key_encrypted:
                    access_key = decrypt_data_in_snowflake(access_key_encrypted, secret_key)
                    secret_key = decrypt_data_in_snowflake(secret_key_encrypted, secret_key)
                else:
                    access_key = None
                    secret_key = None
                return {
                    'username': username,
                    'access_key': access_key if access_key else 'No access key available',
                    'secret_key': secret_key if secret_key else 'No secret key available',
                    'last_generated_date': last_generated_date.strftime('%Y-%m-%d') if last_generated_date else 'No generation date available'
                }
            else:
                return None
        except Exception as e:
            logger.error(f"Error retrieving stored keys: {str(e)}")
            return None

# Rotate keys for users based on conditions
def rotate_keys_for_users():
    conn = get_snowflake_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("""
                USE WAREHOUSE ETL_TEST
            """)
            cur.execute("""
                SELECT USERNAME, LASTKEYGENERATEDDATE, TO_POINTOFCONTACTS
                FROM UTIL_DB.TOOLS.KEY_ROTATION_USERS
                WHERE SKIP_KEY_ROTATION = 'N' 
                AND (LASTKEYGENERATEDDATE IS NULL OR LASTKEYGENERATEDDATE <= CURRENT_DATE - 83)
            """)
            users = cur.fetchall()
            logger.info(f"Snowflake Results:{users}")
            secret_key = 'my_secret_key'
            for user in users:
                username = user[0]
                last_key_generated_date = user[1] if user[1] else datetime.now() - timedelta(days=91)
                email_recipients = user[2].replace(" ", "").split(",")
                logger.info(f"Snowflake Results:{username}{last_key_generated_date}{email_recipients}")
                username = username.strip()


                if last_key_generated_date <= datetime.now() - timedelta(days=83):
                    access_key, secret_key = generate_new_aws_access_key(username)
                    if access_key and secret_key:
                        encrypted_access_key = encrypt_data_in_snowflake(access_key, secret_key)
                        encrypted_secret_key = encrypt_data_in_snowflake(secret_key, secret_key)
                        today_date = datetime.now().strftime('%Y-%m-%d')
                        update_query = f"""
                            UPDATE UTIL_DB.TOOLS.KEY_ROTATION_USERS
                            SET ACCESS_KEY = %s, SECRET_KEY = %s, LASTKEYGENERATEDDATE = %s
                            WHERE USERNAME = %s
                        """
                        cur.execute(update_query, (encrypted_access_key, encrypted_secret_key, today_date, username))
                        logger.info(f"Updated keys for user {username}.")
                        # send_email_notification(
                        #     recipients=email_recipients,
                        #     subject="New AWS Access Keys Generated",
                        #     html=f"<p>Your new AWS Access Key: {access_key}</p><p>Your new Secret Key: {secret_key}</p>"
                        # )
                # deactivate_old_aws_access_keys(username, last_key_generated_date, email_recipients)
            conn.commit()
        except Exception as e:
            logger.error(f"Error rotating keys: {str(e)}")

# Main Lambda handler
def lambda_handler(event, context):
    try:
        if event.get('action') == 'getkeys':
            username = event.get('username')
            if not username:
                return {
                    'statusCode': 400,
                    'body': 'Username not provided'
                }
            keys = get_stored_keys(username)
            if keys:
                return {
                    'statusCode': 200,
                    'body': json.dumps(keys)
                }
            else:
                return {
                    'statusCode': 404,
                    'body': 'No keys found for the specified user'
                }
        else:
            rotate_keys_for_users()
            return {
                'statusCode': 200,
                'body': 'Key rotation and deactivation completed successfully'
            }
    except Exception as e:
        logger.error(f"Error in key rotation process: {str(e)}")
        return {
            'statusCode': 500,
            'body': 'An error occurred during key rotation'
        }
