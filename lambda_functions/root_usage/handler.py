import json
import boto3
import os
import datetime
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib3

sns = boto3.client("sns")
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
OPENSEARCH_ENDPOINT = os.environ["OPENSEARCH_ENDPOINT"]


def ship_to_opensearch(event_doc):
    region = "us-east-1"
    url = f"https://{OPENSEARCH_ENDPOINT}/siem-events/_doc"
    body = json.dumps(event_doc)

    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()
    request = AWSRequest(
        method="POST",
        url=url,
        data=body,
        headers={"Content-Type": "application/json"}
    )
    SigV4Auth(credentials, "es", region).add_auth(request)

    http = urllib3.PoolManager()
    response = http.request(
        "POST",
        url,
        body=body.encode("utf-8"),
        headers=dict(request.headers)
    )
    return response.status


def lambda_handler(event, context):
    detail = event.get("detail", {})
    user_identity = detail.get("userIdentity", {})
    identity_type = user_identity.get("type", "")

    if identity_type != "Root":
        return {"status": "skipped", "reason": "not root account"}

    event_name = detail.get("eventName", "Unknown")
    source_ip = detail.get("sourceIPAddress", "Unknown")
    event_time = detail.get("eventTime", datetime.datetime.utcnow().isoformat())
    user_agent = detail.get("userAgent", "Unknown")
    aws_region = detail.get("awsRegion", "Unknown")

    message = f"""
🚨 CRITICAL SIEM ALERT — Root Account Usage Detected

This is a zero-tolerance event. Root account should never
be used for day-to-day operations.

Event     : {event_name}
Source IP : {source_ip}
Region    : {aws_region}
Time      : {event_time}
User Agent: {user_agent}

Immediate investigation required.
    """

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject="[CRITICAL SIEM ALERT] Root Account Usage Detected",
        Message=message
    )

    event_doc = {
        "timestamp": event_time,
        "event_type": "RootAccountUsage",
        "severity": "CRITICAL",
        "source_ip": source_ip,
        "user": user_identity.get("arn", "root"),
        "details": {
            "event_name": event_name,
            "user_agent": user_agent,
            "aws_region": aws_region,
            "identity_type": identity_type
        }
    }
    status = ship_to_opensearch(event_doc)
    return {"status": "alert_sent", "event": event_name, "opensearch_status": status}