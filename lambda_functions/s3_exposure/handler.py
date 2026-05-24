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
    event_name = detail.get("eventName", "Unknown")
    bucket_name = detail.get("requestParameters", {}).get("bucketName", "Unknown")
    source_ip = detail.get("sourceIPAddress", "Unknown")
    user = detail.get("userIdentity", {}).get("arn", "Unknown")
    event_time = detail.get("eventTime", datetime.datetime.utcnow().isoformat())

    message = f"""
🚨 SIEM ALERT — S3 Public Exposure Detected

Event     : {event_name}
Bucket    : {bucket_name}
Source IP : {source_ip}
User      : {user}

Immediate action required — verify bucket is not publicly accessible.
    """

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject="[SIEM ALERT] S3 Public Exposure Detected",
        Message=message
    )

    event_doc = {
        "timestamp": event_time,
        "event_type": "S3PublicExposure",
        "severity": "HIGH",
        "source_ip": source_ip,
        "user": user,
        "details": {
            "event_name": event_name,
            "bucket_name": bucket_name
        }
    }
    status = ship_to_opensearch(event_doc)
    return {"status": "alert_sent", "opensearch_status": status}