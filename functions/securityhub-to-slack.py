from logging import getLogger, INFO
import boto3
import os
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from base64 import b64decode

logger = getLogger()
logger.setLevel(INFO)


def notify_slack(slack_message):
    parameter_store_name = os.environ["parameter_store_name_for_slack_url"]
    slack_url = get_slack_url(parameter_store_name)
    req = Request(slack_url, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def get_slack_url(parameter_store_name):
    ssm = boto3.client('ssm')
    return ssm.get_parameter(
        Name=parameter_store_name,
        WithDecryption=True
    )["Parameter"]["Value"]


def lambda_handler(event, context):
    message_id = event["detail"]["findings"][0]["Resources"][0]["Id"]
    console_url = 'https://console.aws.amazon.com/securityhub'
    finding = event["detail"]["findings"][0]["Types"][0]
    finding_description = event["detail"]["findings"][0]["Description"]
    finding_time = event["detail"]["findings"][0]["UpdatedAt"]
    account = event["detail"]["findings"][0]["AwsAccountId"]
    region = event["detail"]["findings"][0]["Resources"][0]["Region"]
    finding_type = event["detail"]["findings"][0]["Resources"][0]["Type"]
    message_id = event["detail"]["findings"][0]["Resources"][0]["Id"]
    normalized = event["detail"]["findings"][0]["Severity"]["Normalized"]

    if 1 <= normalized <= 39:
        severity = 'LOW'
        color = '#879596'
    elif 40 <= normalized <= 69:
        severity = 'MEDIUM'
        color = '#ed7211'
    elif 70 <= normalized <= 89:
        severity = 'HIGH'
        color = '#ed7211'
    elif 90 <= normalized <= 100:
        severity = 'CRITICAL'
        color = '#ff0209'
    else:
        severity = 'INFORMATIONAL'
        color = '#007cbc'

    attachments_json = [
        {
            "fallback": f"{console_url}/home?region={region}#/research",
            "pretext": f"*AWS SecurityHub finding in {region} for Account: {account} *",
            "color": color,
            "title": finding,
            "title_link": f"{console_url}/home?region={region}#/findings?search=id%3D{message_id}",
            "text": finding_description,
            "fields": [
                {
                    "title": "Severity",
                    "value": severity,
                    "short": True
                },
                {
                    "title": "Region",
                    "value": region,
                    "short": True
                },
                {
                    "title": "Resource Type",
                    "value": finding_type,
                    "short": True
                },
                {
                    "title": "UpdatedAt",
                    "value": finding_time,
                    "short": True
                }
            ]
        }
    ]
    slack_message = {'attachments': attachments_json}
    if severity == 'CRITICAL' or severity == 'HIGH':
        notify_slack(slack_message)
