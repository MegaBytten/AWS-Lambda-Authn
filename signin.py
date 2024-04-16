###############################################################
######################## Configuration ########################
###############################################################
DYNAMO_USERS_TABLE_NAME = "" # insert your DynamoDB USERS table name
DYNAMO_TOKENS_TABLE_NAME = "" # insert your DynamoDB TOKENS table name
TOKEN_LENGTH = 25 # length of your unique tokens to be generated. Tokens are uppercase + lowercase characters (TOKEN_LENGTH ^ 52)

DYNAMO_USERS_USERNAME = "" # insert name of your Column Name storing USER IDENTIFIERS (username, UID, email) 
DYNAMO_USERS_SALT = "" # insert name of your Column Name storing USER SALTS
DYNAMO_USERS_PASSWORD = "" # insert name of your Column Name storing SHA256-hashed USER PASSWORDS

DETAILED_LOGGING = True # Change this if you only want logs reporting user sign in + token success, or failure.

# TODO - multiple TODOs placed throughout code for error handling or success response
# USER DATA: this script depends on JSON data submitted to API Gateway which must be integrated to the lambda function
# LOGGING: logging used throughout document to provide detailed trouble-shooting and logs in CloudWatch Logs.


###############################################################
########################  Source Code  ########################
###############################################################

import hashlib # for SHA256 hashing
import random # for generating salts and tokens
import string # characters, digits, punctuation for salts
import boto3 # AWS handler
import logging

# # # # GLOBAL VARS # # # #
logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB = boto3.client('dynamodb')
TOKEN = None

def lambda_handler(event, context):
    # # instantiate globals # #
    global DYNAMODB
    
    # # # # CONST VARS # # # #
    SALT_LENGTH = 5
    SALT = None
    ENCODED_PSWD = None
    
    # get user's login data from API Gateway
    username = event.get("username")
    userpass_attempt = event.get("password")
    if DETAILED_LOGGING: logger.info(f"User: {username} attempting to sign in.")
    
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client
    data = DYNAMODB.get_item(
        TableName=DYNAMO_USERS_TABLE_NAME,
        Key={DYNAMO_USERS_USERNAME:{'S':username}}
    )
    
    
    if 'Item' not in data:
        logger.warning(f"User: {username} not found in DB.")
        return {
            'statusCode': 200,
            'body': 'failed',
            'headers': {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Credentials': True, 
                'Content-Type': 'application/json',
            },
        }
    
    # Get SALT and hashed password to compare
    SALT = data['Item'][DYNAMO_USERS_SALT]['S'] # get String value from dynamoDB response
    ENCODED_PSWD = data['Item'][DYNAMO_USERS_PASSWORD]['S'] # get hashed/encoded password from DynamoDB response
    
    # Salt and Hash
    salted_pswd = SALT+userpass_attempt
    salted_pswd = hashlib.sha256(salted_pswd.encode('utf-8')).hexdigest() # hash the salted password

    # TODO: adjust if you want to send a different response on password failed match
    if salted_pswd != ENCODED_PSWD:
        if DETAILED_LOGGING: logger.warning(f"User: {username} failed sign in.")
        return {
            'statusCode': 200,
            'body': 'failed',
            'headers': {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Credentials': True, 
                'Content-Type': 'application/json',
            },
        }
    
    # Successful Sign in. Generate new token.
    signinToken(username)
    logger.info(f"User: {username} successfully signed in. Returning new token.")
    
    # read HTML file as response
    with open('home.html', 'r') as file:
        html = file.read().replace('\n', '')
    
    # TODO change how you want to format response containing token to application
    return {
            'statusCode': 200,
            'body': {
                'html': html,
                'token': TOKEN
            },
            "headers": {
                'Access-Control-Allow-Origin':'*',
                'Access-Control-Allow-Methods':'POST,OPTIONS', # not sure if required?
                "Access-Control-Allow-Credentials": True, # Required for cookies, authorization headers with HTTPS
                'Content-Type':'application/json'
            }
        }
    

def signinToken(username):
    logger.info("Generating token.")
    # # instantiate globals # #
    global DYNAMODB
    global TOKEN
    
    # Get any existing token data from DynamoDB
    data = DYNAMODB.get_item(
        TableName=DYNAMO_TOKENS_TABLE_NAME,
        Key={'username':{'S':username}}
    )
    
    # Check if user has un-expired token, and delete to refresh expiry time.
    if 'Item' in data:
        if DETAILED_LOGGING: logger.info("Pre-existing token found. Deleting old token.")
        response = DYNAMODB.delete_item(
            TableName=DYNAMO_TOKENS_TABLE_NAME,
            Key={'username': {'S': username}}
        )
    
    # Create new token
    TOKEN = ''.join(random.choices(
        string.ascii_letters + string.digits,
        k = TOKEN_LENGTH
    ))
    
    # Write token to DynamoDB
    DYNAMODB.put_item(
        TableName=DYNAMO_TOKENS_TABLE_NAME,
        Item={
            'username': {'S': username},
            'token': {'S': TOKEN}
        }
    )
    
    if DETAILED_LOGGING: logger.info(f"Token generated succesfully, and written to {DYNAMO_TOKENS_TABLE_NAME} DynamoDB TABLE.")