import json
import boto3
import os
import time
import datetime
from decimal import Decimal
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import urllib3

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["DYNAMODB_TABLE"]
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
OPENSEARCH_ENDPOINT = os.environ["OPENSEARCH_ENDPOINT"]
THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", "5"))
WINDOW_SECONDS = int(os.environ.get("WINDOW_SECONDS", "600"))


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super().default(obj)


def ship_to_opensearch(event_doc):
    region = "us-east-1"
    url = f"https://{OPENSEARCH_ENDPOINT}/siem-events/_doc"
    body = json.dumps(event_doc, cls=DecimalEncoder)

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

    error_message = detail.get("errorMessage", "")
    if "Failed authentication" not in error_message:
        return {"status": "skipped", "reason": "not a failed auth"}

    source_ip = detail.get("sourceIPAddress", "unknown")
    user = detail.get("userIdentity", {}).get("arn", "unknown")
    event_time = detail.get("eventTime", datetime.datetime.utcnow().isoformat())

    table = dynamodb.Table(TABLE_NAME)
    response = table.get_item(Key={"source_ip": source_ip})
    existing = response.get("Item")

    if existing:
        new_count = existing["fail_count"] + 1
        table.update_item(
            Key={"source_ip": source_ip},
            UpdateExpression="SET fail_count = :count",
            ExpressionAttributeValues={":count": new_count}
        )
    else:
        new_count = 1
        ttl_timestamp = int(time.time()) + WINDOW_SECONDS
        table.put_item(Item={
            "source_ip": source_ip,
            "fail_count": new_count,
            "first_seen": event_time,
            "ttl": ttl_timestamp
        })

    if new_count >= THRESHOLD:
        message = f"""
🚨 SIEM ALERT — Brute Force Attack Detected

Source IP  : {source_ip}
User       : {user}
Failures   : {new_count} failed attempts
Time       : {event_time}
Window     : Last {WINDOW_SECONDS // 60} minutes

Immediate action required — consider blocking this IP.
        """

        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"[SIEM ALERT] Brute Force Detected from {source_ip}",
            Message=message
        )

        event_doc = {
            "timestamp": event_time,
            "event_type": "BruteForce",
            "severity": "HIGH",
            "source_ip": source_ip,
            "user": user,
            "details": {
                "fail_count": int(new_count),
                "window_minutes": WINDOW_SECONDS // 60
            }
        }
        status = ship_to_opensearch(event_doc)
        return {"status": "alert_sent", "ip": source_ip,
                "count": int(new_count), "opensearch_status": status}

    return {"status": "recorded", "ip": source_ip, "count": int(new_count)}