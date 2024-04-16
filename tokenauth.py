###############################################################
######################## Configuration ########################
###############################################################
DYNAMO_TOKENS_TABLE_NAME = "" # insert your DynamoDB TOKENS table name

DYNAMO_TOKENS_USERNAME = "" # insert name of your Column Name storing TOKEN IDENTIFIERS (username, UID, email) 
DYNAMO_TOKENS_TOKEN = "" # insert name of your Column Name storing TOKEN tokens

DETAILED_LOGGING = True # Change this if you only want logs reporting user sign in + token success, or failure.

HTML_RESPONSE = "home.html" # insert name of HTML file you want to response with, configure if you want to return JSON application data instead

# TODO - multiple TODOs placed throughout code for error handling or success response
# USER DATA: this script depends on JSON data submitted to API Gateway which must be integrated to the lambda function
# LOGGING: logging used throughout document to provide detailed trouble-shooting and logs in CloudWatch Logs.


###############################################################
########################  Source Code  ########################
###############################################################

import boto3 # AWS handler
import logging

# # # # GLOBAL VARS # # # #
logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB = boto3.client('dynamodb')
TOKEN = None

def lambda_handler(event, context):
    # # instantiate globals # #
    global DYNAMODB, TOKEN
    
    # Return problem, no token provided
    if "username" not in event or "token" not in event:
        logger.warning("No token or username provided.")
        return {
            'statusCode': 200,
            'body': 'failed',
            'headers': {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Credentials': True, 
                'Content-Type': 'application/json',
            },
        }
    
    # get user's login data from API Gateway
    token_attempt = event.get("token")
    username = event.get("username")
    
    if DETAILED_LOGGING: logger.info(f"User: {username} attempting to auth with Token.")
    
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client
    data = DYNAMODB.get_item(
        TableName=DYNAMO_TOKENS_TABLE_NAME,
        Key={DYNAMO_TOKENS_USERNAME:{'S':username}}
    )
    
    
    if 'Item' not in data:
        logger.warning(f"User: {username} not found in Token DB.")
        return {
            'statusCode': 200,
            'body': 'failed',
            'headers': {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Credentials': True, 
                'Content-Type': 'application/json',
            },
        }
    
    # Get TOKEN from DB to compare
    TOKEN = data['Item'][DYNAMO_TOKENS_TOKEN]['S'] # get String value of TOKEN from dynamoDB response

    # Attempt sign in
    if token_attempt != TOKEN:
        logger.warning(f"User: {username} failed to token authorise.")
        return {
            'statusCode': 200,
            'body': 'failed',
            'headers': {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Credentials': True, 
                'Content-Type': 'application/json',
            },
        }
    
    # Successful Sign in. Return data.
    logger.info(f"User: {username} successfully signed in. Returning HTML.")
    
    # TODO: Client response from Lambda
    #   > Change how you want to format response containing token to application
    #   > Default behaviour returns a basic HTML web page
    with open(HTML_RESPONSE, 'r') as file:
        html = file.read()
    
    return {
            'statusCode': 200,
            'body': {
                'html': html
            },
            "headers": {
                'Access-Control-Allow-Origin':'*',
                'Access-Control-Allow-Methods':'POST,OPTIONS', # not sure if required?
                "Access-Control-Allow-Credentials": True, # Required for cookies, authorization headers with HTTPS
                'Content-Type':'application/json'
            }
        }
