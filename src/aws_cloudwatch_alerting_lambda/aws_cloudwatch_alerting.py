# Based on:
# https://raw.githubusercontent.com/terraform-aws-modules/terraform-aws-notify-slack/659b4aac4aee2ab026d9f117f52a90cfc7ae0cff/functions/notify_slack.py
# installed by script
from __future__ import print_function
import os, boto3, json, base64, argparse, sys, socket, uuid
import urllib.request, urllib.parse
import sys
import logging
from datetime import datetime
from datetime import timedelta
from datetime import date

https_prefix = "https://"
cloudwatch_url = "https://console.aws.amazon.com/cloudwatch/home?region="
date_format = "%Y-%m-%dT%H:%M:%S.%f%z"
date_format_display = "%Y-%m-%dT%H:%M:%S"
log_level = os.environ["LOG_LEVEL"] if "LOG_LEVEL" in os.environ else "INFO"
correlation_id = str(uuid.uuid4())
information_source_icon = ":information_source:"


# Initialise logging
def setup_logging(logger_level):
    """Set the default logger with json output."""
    the_logger = logging.getLogger()
    for old_handler in the_logger.handlers:
        the_logger.removeHandler(old_handler)

    new_handler = logging.StreamHandler(sys.stdout)

    hostname = socket.gethostname()

    json_format = (
        '{ "timestamp": "%(asctime)s", "log_level": "%(levelname)s", "message": "%(message)s", '
        f'"environment": "{args.environment}","application": "{args.application}", '
        f'"module": "%(module)s", "process":"%(process)s", '
        f'"thread": "[%(thread)s]", "hostname": "{hostname}" }}'
    )

    new_handler.setFormatter(logging.Formatter(json_format))
    the_logger.addHandler(new_handler)
    new_level = logging.getLevelName(logger_level.upper())
    the_logger.setLevel(new_level)

    if the_logger.isEnabledFor(logging.DEBUG):
        # Log everything from boto3
        boto3.set_stream_logger()
        the_logger.debug(f'Using boto3", "version": "{boto3.__version__}')

    return the_logger


def get_parameters():
    """Define and parse command line args."""
    parser = argparse.ArgumentParser(
        description="Send HTME SQS messages for defined or default topics."
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--aws-profile", default="default")
    parser.add_argument("--aws-region", default="eu-west-2")
    parser.add_argument("--environment", default="NOT_SET", help="Environment value")
    parser.add_argument("--application", default="NOT_SET", help="Application")

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_PROFILE" in os.environ:
        _args.aws_profile = os.environ["AWS_PROFILE"]

    if "AWS_REGION" in os.environ:
        _args.aws_region = os.environ["AWS_REGION"]

    if "ENVIRONMENT" in os.environ:
        _args.environment = os.environ["ENVIRONMENT"]

    if "APPLICATION" in os.environ:
        _args.application = os.environ["APPLICATION"]

    return _args


args = get_parameters()
logger = setup_logging(log_level)


# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ["AWS_REGION"]
    logger.info(
        f'Decrypting URL", "encrypted_url": "{encrypted_url}", "region": "{region}", "correlation_id": "{correlation_id}'
    )

    try:
        kms = boto3.client("kms", region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))[
            "Plaintext"
        ]
        logger.info(
            f'Decrypted URL", "encrypted_url": "{encrypted_url}", "plaintext": "{plaintext}", "region": "{region}", "correlation_id": "{correlation_id}'
        )
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")
        logger.error(
            f'Failed to decrypt URL with KMS", "encrypted_url": "{encrypted_url}", "region": "{region}", "correlation_id": "{correlation_id}'
        )


def config_notification(message, region, payload):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing config notification", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    no_emojis = {
        "COMPLIANT": "Compliant",
        "NOT_APPLICABLE": "N/A",
        "NON_COMPLIANT": "Non-Compliant",
    }
    emojis = {
        "COMPLIANT": ":white_check_mark:*Compliant*:white_check_mark:",
        "NOT_APPLICABLE": ":white_check_mark:*N/A*:white_check_mark:",
        "NON_COMPLIANT": ":x:*Non-Compliant*:x:",
    }
    config_rule_name = message["newEvaluationResult"]["evaluationResultIdentifier"][
        "evaluationResultQualifier"
    ]["configRuleName"]
    # If an object has just been created, it does not have a 'complianceType'.
    config_old_state = "NOT_APPLICABLE"
    if message["oldEvaluationResult"] != None:
        config_old_state = message["oldEvaluationResult"]["complianceType"]
    config_new_state = message["newEvaluationResult"]["complianceType"]
    # We constantly get spammed with restricted-ssh periodically going from NON_COMPLIANT to NOT_APPLICABLE
    if config_new_state == "NOT_APPLICABLE":
        print("DEBUG: new state NOT_APPLICABLE message - exiting.")
        quit()
    elif config_old_state == "NOT_APPLICABLE" and config_new_state == "COMPLIANT":
        # TT: inserted this because we are not really interested in the creation of a new resource whose state is COMPLIANT
        print(
            "DEBUG: old state NOT_APPLICABLE & new state COMPLIANT message - exiting."
        )
        quit()
    config_url = (
        https_prefix
        + region
        + ".console.aws.amazon.com/config/home#/rules/rule-details/"
        + urllib.parse.quote_plus(
            message["newEvaluationResult"]["evaluationResultIdentifier"][
                "evaluationResultQualifier"
            ]["configRuleName"]
        )
    )

    payload["blocks"] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "AWS Config Compliance Change detected " + config_rule_name,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "AWS Config Compliance Rule ["
                    + config_rule_name
                    + "] has changed from ["
                    + no_emojis[config_old_state]
                    + "] to ["
                    + emojis[config_new_state]
                    + "]\nThis script can't tell if everything is compliant or not. For full details check the AWS Console: "
                    + config_url,
                }
            ],
        },
    ]
    return payload


def config_cloudwatch_event_notification(message, region, payload):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing cloudwatch event notification", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    # see: https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html
    # see also: https://docs.aws.amazon.com/config/latest/developerguide/example-sns-notification.html
    title = "AWS Config CloudWatch Event."
    value = "Unidentified"
    config_url = (
        https_prefix
        + region
        + ".console.aws.amazon.com/config/home?region="
        + region
        + "#/dashboard/"
    )

    message_type = message["messageType"]

    if message_type == "ConfigurationItemChangeNotification":
        change_type = message["configurationItemDiff"]["changeType"]
        changed_properties = message["configurationItemDiff"]["changedProperties"]
        configuration_item = message["configurationItem"]
        resource_type = configuration_item["resourceType"]
        resource_id = configuration_item["resourceId"]
        capture_time = configuration_item["configurationItemCaptureTime"]
        value = (
            "Change of type ["
            + change_type
            + "] on a resource of type ["
            + resource_type
            + "]"
        )
        config_url = (
            https_prefix
            + region
            + ".console.aws.amazon.com/config/home?region="
            + region
            + "#/timeline/"
            + resource_type
            + "/"
            + resource_id
            + "?time="
            + capture_time
        )

        if (
            "resourceName" in configuration_item
            and configuration_item["resourceName"] is not None
        ):
            resource_name = configuration_item["resourceName"]
            value = value + " that has name [" + resource_name + "]"

        if "ResourceCompliance" in resource_type:
            # we will see the compliance/non-compliance via a call to function config_notification(message, region)
            quit()
        elif "NetworkInterface" in resource_type:
            # we see too many of these DELETE/CREATE pairs going-on all the time (some kind of continual 'under-the-hood' AWS
            # activity ?) to be worth alerting on...
            quit()
        elif change_type == "UPDATE":
            if "Relationships.0" in changed_properties:
                # not interested in this sort of update, which is due to a 'relationship' with a genuine change (that should itself have been notified).
                # a typical sequence is a NetworkInterface DELETE/CREATE (some kind of continual 'under-the-hood' AWS activity, as indicated & trapped above ?)
                # that triggers an UPDATE to some/all of: SG, Instance, Subnet, VPC; due to each having a relationship to that NetworkInterface
                # quit()

                relationships_0 = changed_properties["Relationships.0"]
                relationships_0_change_type = relationships_0["changeType"]
                previous_value = relationships_0["previousValue"]
                updated_value = relationships_0["updatedValue"]
                relationship_value = " due to at least one relationship"

                if "name" in previous_value:
                    relationship_value = (
                        relationship_value + " that [" + previous_value["name"] + "]"
                    )
                elif "name" in updated_value:
                    relationship_value = (
                        relationship_value + " that [" + updated_value["name"] + "]"
                    )

                value = (
                    value
                    + relationship_value
                    + " whose own change type is ["
                    + relationships_0_change_type
                    + "]"
                )

            elif (
                "Configuration.AvailableIpAddressCount" in changed_properties
                and len(changed_properties) == 1
            ):
                # same as above comment: a 'relationship' update specifically on a subnet, telling us the number of its
                # NetworkInterfaces has changed
                # quit()

                relationship_value = " due to a related AvailableIpAddressCount change"
                value = value + relationship_value
            elif (
                "Configuration.NetworkInterfaces.0" in changed_properties
                and len(changed_properties) == 2
            ):
                # same as above comment: a 'relationship' update specifically on an instance this time, telling us one
                # NetworkInterface been deleted & replaced by a new one
                # quit()

                relationship_value = " due to a related NetworkInterfaces change"
                value = value + relationship_value

        value = value + "."

    elif message_type == "ConfigurationSnapshotDeliveryFailed":
        # guess we would want to be alerted about this...
        value = json.dumps(message)
    elif message_type == "ComplianceChangeNotification":
        # assuming this is covered by a call to 'config_notification(message, region)'...
        quit()
    elif (
        message_type == "ConfigRulesEvaluationStarted"
        or message_type == "ConfigurationSnapshotDeliveryCompleted"
        or message_type == "ConfigurationSnapshotDeliveryStarted"
        or message_type == "ConfigurationHistoryDeliveryCompleted"
    ):
        # we do not want to be alerted about any of these...
        quit()
    else:
        return custom_notification(message, region, payload)

    payload["blocks"] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": value
                    + "\nFor full details check the AWS Console ["
                    + config_url
                    + "].",
                }
            ],
        },
    ]
    return payload


def config_cloudwatch_alarm_notification(
    message, region, prowler_slack_channel, payload
):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing cloudwatch notification", "dumped_message": {dumped_message}, "region": "{region}", "prowler_slack_channel": {prowler_slack_channel}, "correlation_id": "{correlation_id}'
    )

    trigger_object = message["Trigger"] if "Trigger" in message else None

    if (
        trigger_object is not None
        and "Namespace" in trigger_object
        and trigger_object["Namespace"] == "Prowler/Monitoring"
    ):
        payload = config_prowler_cloudwatch_alarm_notification(message, region, payload)
        payload["channel"] = prowler_slack_channel
    else:
        payload = config_custom_cloudwatch_alarm_notification(message, region, payload)

    return payload


def is_alarm_suppressed(tags, today, now):
    if not tags or len(tags) == 0:
        logger.info(
            f'Alarm notification not supressed due to no tags", "tags": "{tags}", "correlation_id": "{correlation_id}'
        )
        return False

    active_days = next(
        (tag["Value"] for tag in tags if tag["Key"] == "active_days" and tag["Value"]),
        "NOT_SET",
    )
    do_not_alert_before = next(
        (
            tag["Value"]
            for tag in tags
            if tag["Key"] == "do_not_alert_before" and tag["Value"]
        ),
        "NOT_SET",
    )
    do_not_alert_after = next(
        (
            tag["Value"]
            for tag in tags
            if tag["Key"] == "do_not_alert_after" and tag["Value"]
        ),
        "NOT_SET",
    )

    logger.info(
        f'Retrieved tag values", "active_days": "{active_days}", "do_not_alert_before": "{do_not_alert_before}", "do_not_alert_after": "{do_not_alert_after}", "correlation_id": "{correlation_id}'
    )

    date_today = today.strftime("%A").lower()
    time_now = now.strftime("%H%M")

    logger.info(
        f'Parsed current date and time", "date_today": "{date_today}", "time_now": "{time_now}", "correlation_id": "{correlation_id}'
    )

    if active_days and active_days != "NOT_SET":
        days_array = active_days.lower().split("+")
        if date_today not in days_array:
            logger.info(
                f'Alarm notification supressed due to active_days", "date_today": "{date_today}", "active_days": "{active_days}", "correlation_id": "{correlation_id}'
            )
            return True

    if do_not_alert_before and do_not_alert_before != "NOT_SET":
        if int(time_now) < int(do_not_alert_before.replace(":", "")):
            logger.info(
                f'Alarm notification supressed due to do_not_alert_before", "time_now": "{time_now}", "do_not_alert_before": "{do_not_alert_before}", "correlation_id": "{correlation_id}'
            )
            return True

    if do_not_alert_after and do_not_alert_after != "NOT_SET":
        if int(time_now) > int(do_not_alert_after.replace(":", "")):
            logger.info(
                f'Alarm notification supressed due to do_not_alert_after", "time_now": "{time_now}", "do_not_alert_after": "{do_not_alert_after}", "correlation_id": "{correlation_id}'
            )
            return True

    logger.info(
        f'Alarm notification not supressed due to tag values", "tags": "{tags}", "correlation_id": "{correlation_id}'
    )

    return False


def get_tags_for_cloudwatch_alarm(cw_client, alarm_arn):
    logger.info(
        f'Getting tags for cloudwatch alarm", "alarm_arn": "{alarm_arn}", "correlation_id": "{correlation_id}'
    )

    tags = cw_client.list_tags_for_resource(ResourceARN=alarm_arn)
    logger.info(
        f'Retrieved tags for cloudwatch alarm", "alarm_arn": "{alarm_arn}", "tags": "{tags}", "correlation_id": "{correlation_id}'
    )
    return tags["Tags"] if tags else []


def config_custom_cloudwatch_alarm_notification(message, region, payload):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing custom cloudwatch notification", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    slack_channel_main = os.environ["AWS_SLACK_CHANNEL_MAIN"]
    slack_channel_critical = os.environ["AWS_SLACK_CHANNEL_CRITICAL"]
    environment_name = os.environ["AWS_ENVIRONMENT"]
    log_critical_with_here = (
        os.environ["AWS_LOG_CRITICAL_WITH_HERE"]
        if "AWS_LOG_CRITICAL_WITH_HERE" in os.environ
        else "NOT_SET"
    )

    logger.info(
        f'Retrieved aws event variables", "slack_channel_main": "{slack_channel_main}", "slack_channel_critical": "{slack_channel_critical}", "slack_channel_main": "{slack_channel_main}", "log_critical_with_here": "{log_critical_with_here}", "correlation_id": "{correlation_id}'
    )

    alarm_name = message["AlarmName"]

    cw_client = boto3.client("cloudwatch", region_name=region)
    tags = get_tags_for_cloudwatch_alarm(cw_client, message["AlarmArn"])

    if is_alarm_suppressed(tags, date.today(), datetime.now()):
        logger.info(
            f'Exiting script normally due to suppressed alarm", "correlation_id": "{correlation_id}'
        )
        sys.exit(0)

    severity = next(
        (tag["Value"] for tag in tags if tag["Key"] == "severity" and tag["Value"]),
        "NOT_SET",
    )
    notification_type = next(
        (
            tag["Value"]
            for tag in tags
            if tag["Key"] == "notification_type" and tag["Value"]
        ),
        "NOT_SET",
    )
    active_days = next(
        (tag["Value"] for tag in tags if tag["Key"] == "active_days" and tag["Value"]),
        "NOT_SET",
    )
    do_not_alert_before = next(
        (
            tag["Value"]
            for tag in tags
            if tag["Key"] == "do_not_alert_before" and tag["Value"]
        ),
        "NOT_SET",
    )
    do_not_alert_after = next(
        (
            tag["Value"]
            for tag in tags
            if tag["Key"] == "do_not_alert_after" and tag["Value"]
        ),
        "NOT_SET",
    )

    alarm_url = (
        cloudwatch_url + region + "#s=Alarms&alarm=" + alarm_name.replace(" ", "%20")
    )

    icon = ":warning:"
    here = ""
    slack_channel = slack_channel_main

    logger.info(
        f'Set slack message variables", "severity": "{severity}", "notification_type": "{notification_type}", "alarm_name": "{alarm_name}", "alarm_url": "{alarm_url}", "icon": "{icon}", "slack_channel": "{slack_channel}", "correlation_id": "{correlation_id}'
    )

    if notification_type.lower() == "information":
        icon = information_source_icon
    elif notification_type.lower() == "error":
        icon = ":fire:"
        if severity.lower() == "high" or severity.lower() == "critical":
            slack_channel = slack_channel_critical
    elif severity.lower() == "critical":
        slack_channel = slack_channel_critical

    if (
        slack_channel == slack_channel_critical
        and log_critical_with_here
        and log_critical_with_here.lower() == "true"
    ):
        here = "@here "

    title = f'{here}*{environment_name.upper()}*: "_{alarm_name}_" in {region}'

    logger.info(f'Set title", "title": "{title}", "correlation_id": "{correlation_id}')

    trigger_time = (
        datetime.strptime(message["StateChangeTime"], date_format).strftime(
            date_format_display
        )
        if "StateChangeTime" in message
        else "NOT_SET"
    )

    logger.info(
        f'Set trigger time", "trigger_time": "{trigger_time}", "correlation_id": "{correlation_id}'
    )

    payload["channel"] = slack_channel
    blocks = []
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title,
            },
        }
    )

    alarm_url = alarm_url.replace("|", "%7C")

    if "username" in payload and "AWS Breakglass Alerts" in payload["username"]:
        payload["username"] = f"AWS DataWorks Breakglass Alerts - {environment_name}"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*AWS Console link*: <{alarm_url}|Click here>",
                    },
                    {"type": "mrkdwn", "text": f"*Trigger time*: {trigger_time}"},
                ],
            }
        )
    elif alarm_name.startswith("Security Hub finding"):
        finding_url = f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings?search=ComplianceStatus%3D%255Coperator%255C%253AEQUALS%255C%253AWARNING%26ComplianceStatus%3D%255Coperator%255C%253AEQUALS%255C%253AERROR"
        payload["username"] = f"AWS DataWorks Security Hub Alerts - {environment_name}"
        payload["icon_emoji"] = ":old_key:"
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*AWS Console link*: <{finding_url}|Click here>",
                    },
                    {"type": "mrkdwn", "text": f"*Trigger time*: {trigger_time}"},
                ],
            }
        )
    else:
        payload["username"] = f"AWS DataWorks Service Alerts - {environment_name}"
        payload["icon_emoji"] = icon
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*AWS Console link*: <{alarm_url}|Click here>",
                    },
                    {"type": "mrkdwn", "text": f"*Trigger time*: {trigger_time}"},
                    {"type": "mrkdwn", "text": f"*Severity*: {severity}"},
                    {"type": "mrkdwn", "text": f"*Type*: {notification_type}"},
                    {"type": "mrkdwn", "text": f"*Active days*: {active_days}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Suppress before*: {do_not_alert_before}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Suppress after*: {do_not_alert_after}",
                    },
                ],
            }
        )

    payload["blocks"] = blocks
    return payload


def config_prowler_cloudwatch_alarm_notification(message, region, payload):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing prowler notification", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    # See matching patterns at: https://github.com/dwp/terraform-aws-prowler-monitoring/blob/master/main.tf
    cloudwatch_metric_filters = {
        "3.1 Unauthorized API calls": {
            "filter": '{($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")}',
            "severity": "Medium",
        },
        "3.2 Management Console sign-in without MFA": {
            "filter": '{$.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No"}',
            "severity": "Medium",
        },
        "3.3 usage of root account": {
            "filter": '{$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}',
            "severity": "Critical",
        },
        "3.4 IAM policy changes": {
            "filter": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
            "severity": "Low",
        },
        "3.5 CloudTrail configuration changes": {
            "filter": "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}",
            "severity": "High",
        },
        "3.6 AWS Management Console authentication failures": {
            "filter": '{($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication")}',
            "severity": "Low",
        },
        "3.7 disabling or scheduled deletion of customer created CMKs": {
            "filter": "{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}",
            "severity": "Medium",
        },
        "3.8 S3 bucket policy changes": {
            "filter": "{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication))}",
            "severity": "Low",
        },
        "3.9 AWS Config configuration changes": {
            "filter": "{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}",
            "severity": "Low",
        },
        "3.10 security group changes": {
            "filter": "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}",
            "severity": "Low",
        },
        "3.11 changes to Network Access Control Lists (NACL)": {
            "filter": "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}",
            "severity": "Low",
        },
        "3.12 changes to network gateways": {
            "filter": "{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)}",
            "severity": "Low",
        },
        "3.13 route table changes": {
            "filter": "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}",
            "severity": "Low",
        },
        "3.14 VPC changes": {
            "filter": "{($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink)}",
            "severity": "Low",
        },
    }

    environment_name = os.environ["AWS_ENVIRONMENT"]
    alarm_name = message["AlarmName"]
    title = f'*{environment_name.upper()}*: "_{alarm_name}_" in {region}'

    logger.info(f'Set title", "title": "{title}", "correlation_id": "{correlation_id}')

    # providing a link back to the alarm is not of much use...
    alarm_url = (
        cloudwatch_url + region + "#s=Alarms&alarm=" + alarm_name.replace(" ", "%20")
    )

    # ...so let's construct a useful link: back to the cloudwatch log that actually triggered the alarm...
    alarm_datetime_full = message["StateChangeTime"]
    # time is in the format: 2019-03-29T11:47:40.755+0000; let's lose the bit after the seconds...
    alarm_datetime = alarm_datetime_full[:19]
    cloudwatch_logs_search_end_datetime_object = datetime.strptime(
        alarm_datetime, "%Y-%m-%dT%H:%M:%S"
    )
    # assume we will have to search in the logs going back over 15 mins, which is the period within which AWS
    # guarantees to have fired the alarm...
    cloudwatch_logs_search_start_datetime_object = (
        cloudwatch_logs_search_end_datetime_object + timedelta(minutes=-15)
    )

    trigger_time = (
        datetime.strptime(message["StateChangeTime"], date_format).strftime(
            date_format_display
        )
        if "StateChangeTime" in message
        else "NOT_SET"
    )

    aws_account_id = message["AWSAccountId"]
    cloudwatch_log_group = "cloudTrail"
    cloudwatch_log_stream = aws_account_id + "_CloudTrail_" + region
    cloudwatch_metric_filter = ""
    severity = "NOT_SET"
    icon = ":question:"

    if alarm_name in cloudwatch_metric_filters:
        cloudwatch_metric_filter = cloudwatch_metric_filters[alarm_name]["filter"]
        severity = cloudwatch_metric_filters[alarm_name]["severity"]
        if severity.lower() == "low":
            icon = information_source_icon
        elif severity.lower() == "medium":
            icon = ":closed_lock_with_key:"
        elif severity.lower() == "high":
            icon = ":lock:"
        elif severity.lower() == "critical":
            icon = ":unlock:"

    cloudwatch_metric_filter = cloudwatch_metric_filter.replace(" ", "%20")
    cloudwatch_metric_filter = cloudwatch_metric_filter.replace("=", "%3D")

    cloudwatch_log_url = (
        cloudwatch_url
        + region
        + "#logEventViewer:group="
        + cloudwatch_log_group
        + ";stream="
        + cloudwatch_log_stream
        + ";filter="
        + cloudwatch_metric_filter
        + ";start="
        + cloudwatch_logs_search_start_datetime_object.strftime(date_format_display)
        + ";end="
        + cloudwatch_logs_search_end_datetime_object.strftime(date_format_display)
    )

    cloudwatch_log_url = cloudwatch_log_url.replace("|", "%7C")

    payload["username"] = f"AWS DataWorks Security Alerts - {environment_name}"
    payload["icon_emoji"] = icon
    payload["blocks"] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*AWS Console link*: <{cloudwatch_log_url}|Click here>",
                },
                {"type": "mrkdwn", "text": f"*Trigger time*: {trigger_time}"},
                {"type": "mrkdwn", "text": f"*Severity*: {severity}"},
                {"type": "mrkdwn", "text": f"*Type*: Security notification"},
            ],
        },
    ]
    return payload


def guardduty_notification(message, region, payload):
    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing guard duty notification", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    gd_finding_detail_type = message["detail"]["type"]
    gd_finding_detail_service_action_type = message["detail"]["service"]["action"][
        "actionType"
    ]
    gd_finding_detail_resource_type = message["detail"]["resource"]["resourceType"]
    gd_url = (
        https_prefix
        + region
        + ".console.aws.amazon.com/guardduty/home?region="
        + region
        + "#/findings"
    )

    payload["blocks"] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "AWS GuardDuty Finding Type [" + gd_finding_detail_type + "]",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Finding of type ["
                    + gd_finding_detail_type
                    + "] due to an action of type ["
                    + gd_finding_detail_service_action_type
                    + "] on a resource of type ["
                    + gd_finding_detail_resource_type
                    + "].\nFor full details check the AWS Console ["
                    + gd_url
                    + "].",
                }
            ],
        },
    ]
    return payload


def app_notification(slack_message, region, payload):
    dumped_slack_message = get_escaped_json_string(slack_message)
    logger.info(
        f'Processing app notification", "slack_message": "{dumped_slack_message}", "correlation_id": "{correlation_id}'
    )

    recognised_apps = {
        "Security": "",
        "Payment": "",
        "Pipeline": "",
        "TransferToPensionAge": "",
        "MI12CaseControl": "",
        "QLR": "",
        "ReleaseComparison": "",
    }

    message = slack_message["slack"]
    app = message["application"]

    if app not in recognised_apps:
        quit()

    app_function = message["function"]
    app_function_message_type = message["messageType"]
    app_function_message = message["message"]
    title = "[" + app + "] application notification."

    dumped_app_function_message = get_escaped_json_string(app_function_message)
    logger.info(
        f'Created app notification", "app_function_message": "{dumped_app_function_message}", "correlation_id": "{correlation_id}'
    )

    payload["blocks"] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title,
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*{app_function} {app_function_message_type}*: {app_function_message}",
                }
            ],
        },
    ]
    return payload


def custom_notification(message, region, payload):
    global date_format_display

    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Processing custom notification", "dumped_message": {dumped_message}, "correlation_id": "{correlation_id}", "region": "{region}'
    )

    tags = []
    keys = ["active_days", "do_not_alert_before", "do_not_alert_after"]
    for key in keys:
        if key in message:
            tags.append({"Key": key, "Value": message[key]})

    if is_alarm_suppressed(tags, date.today(), datetime.now()):
        logger.info(
            f'Exiting script normally due to suppressed alarm", "correlation_id": "{correlation_id}'
        )
        sys.exit(0)

    environment_name = os.environ["AWS_ENVIRONMENT"]
    slack_channel_main = os.environ["AWS_SLACK_CHANNEL_MAIN"]
    slack_channel_critical = os.environ["AWS_SLACK_CHANNEL_CRITICAL"]

    active_days = message["active_days"] if "active_days" in message else "NOT_SET"
    do_not_alert_before = (
        message["do_not_alert_before"]
        if "do_not_alert_before" in message
        else "NOT_SET"
    )
    do_not_alert_after = (
        message["do_not_alert_after"] if "do_not_alert_after" in message else "NOT_SET"
    )
    logger.info(
        f'Set slack message suppression overrides", "active_days": "{active_days}", "do_not_alert_before": "{do_not_alert_before}", "do_not_alert_after": "{do_not_alert_after}", "correlation_id": "{correlation_id}'
    )

    severity = message["severity"] if "severity" in message else "Medium"
    notification_type = (
        message["notification_type"] if "notification_type" in message else "Warning"
    )
    slack_username = (
        message["slack_username"]
        if "slack_username" in message
        else f"AWS DataWorks Service Alerts - {environment_name}"
    )
    icon_override = (
        message["icon_override"] if "icon_override" in message else "NOT_SET"
    )
    slack_channel_override = (
        message["slack_channel_override"]
        if "slack_channel_override" in message
        else "NOT_SET"
    )
    log_with_here = (
        message["log_with_here"] if "log_with_here" in message else "NOT_SET"
    )
    title_text = message["title_text"] if "title_text" in message else "NOT_SET"

    icon = ":warning:"
    here = ""
    slack_channel = slack_channel_main

    if icon_override != "NOT_SET":
        icon = icon_override
    elif notification_type.lower() == "information":
        icon = information_source_icon
    elif notification_type.lower() == "error":
        icon = ":fire:"

    if slack_channel_override != "NOT_SET":
        slack_channel = slack_channel_override
    elif notification_type.lower() == "error":
        if severity.lower() == "high" or severity.lower() == "critical":
            slack_channel = slack_channel_critical
    elif notification_type.lower() != "information" and severity.lower() == "critical":
        slack_channel = slack_channel_critical

    trigger_time = datetime.now().strftime(date_format_display)

    logger.info(
        f'Set slack message variables", "severity": "{severity}", "notification_type": "{notification_type}", "slack_username": "{slack_username}", "trigger_time": "{trigger_time}", "icon": "{icon}", "slack_channel": "{slack_channel}", "correlation_id": "{correlation_id}'
    )

    if log_with_here.lower() == "true":
        here = "@here "

    title = f'{here}*{environment_name.upper()}*: "_{title_text}_" in {region}'
    logger.info(f'Set title", "title": "{title}", "correlation_id": "{correlation_id}')

    payload["channel"] = slack_channel
    blocks = []
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": title,
            },
        }
    )

    payload["username"] = slack_username
    payload["icon_emoji"] = icon

    elements = [
        {"type": "mrkdwn", "text": f"*Severity*: {severity}"},
        {"type": "mrkdwn", "text": f"*Type*: {notification_type}"},
        {"type": "mrkdwn", "text": f"*Active days*: {active_days}"},
        {
            "type": "mrkdwn",
            "text": f"*Suppress before*: {do_not_alert_before}",
        },
        {
            "type": "mrkdwn",
            "text": f"*Suppress after*: {do_not_alert_after}",
        },
    ]

    if "custom_elements" in message:
        for custom_element in message:
            if "key" in custom_element and "value" in custom_element:
                key = custom_element["key"]
                key = custom_element["value"]
                elements.append({"type": "mrkdwn", "text": f"*{key}*: {value}"})

    blocks.append(
        {
            "type": "context",
            "elements": elements,
        }
    )

    payload["blocks"] = blocks
    return payload


# Send a message to a slack channel
def notify_slack(message, region):

    if "slack" in message:
        # this is some info from one of our apps, intended for an app-specific slack channel...

        logger.info(f'Processing app event", "correlation_id": "{correlation_id}')

        slack_url = os.environ["APP_INFO_SLACK_WEBHOOK_URL"]
        if not slack_url.startswith("http"):
            slack_url = decrypt(slack_url)

        slack_channel = os.environ["APP_INFO_SLACK_CHANNEL"]
        slack_username = os.environ["APP_INFO_SLACK_USERNAME"]

        payload = {
            "channel": slack_channel,
            "username": slack_username,
            "icon_emoji": os.environ["APP_INFO_SLACK_ICON_EMOJI"]
            if "APP_INFO_SLACK_ICON_EMOJI" in os.environ
            else ":aws:",
        }

        dumped_payload = get_escaped_json_string(payload)
        logger.info(
            f'Created initial app slack payload", "payload": "{dumped_payload}", "app_slack_url": "{slack_url}", "app_slack_channel": "{slack_channel}", "app_slack_username": "{slack_username}", "correlation_id": "{correlation_id}'
        )

        payload = app_notification(message, region, payload)
    else:
        # this is a status update from AWS...

        logger.info(f'Processing aws event", "correlation_id": "{correlation_id}')

        slack_url = os.environ["STATUS_SLACK_WEBHOOK_URL"]

        if not slack_url.startswith("http"):
            slack_url = decrypt(slack_url)

        slack_channel = os.environ["STATUS_SLACK_CHANNEL"]
        slack_username = os.environ["STATUS_SLACK_USERNAME"]

        payload = {
            "channel": slack_channel,
            "username": slack_username,
            "icon_emoji": os.environ["STATUS_SLACK_ICON_EMOJI"]
            if "STATUS_SLACK_ICON_EMOJI" in os.environ
            else ":aws:",
        }

        dumped_payload = get_escaped_json_string(payload)
        logger.info(
            f'Created initial slack payload", "payload": "{dumped_payload}", "slack_url": "{slack_url}", "slack_channel": "{slack_channel}", "slack_username": "{slack_username}", "correlation_id": "{correlation_id}'
        )

        if "detail-type" in message and message["detail-type"] == "GuardDuty Finding":
            payload = guardduty_notification(message, region, payload)
        elif "configRuleName" in message:
            # this is a compliance/non-compliance AWS Config message...
            payload = config_notification(message, region, payload)
        elif (
            "messageType" in message
            and message["messageType"] == "ConfigurationItemChangeNotification"
        ):
            # this is an AWS Config CloudWatch Event, specifically a config item change notification
            # that unfortunately has to be triggered on any resource type for which we have defined an AWS Config compliance
            # rule (see aws_config_setup.tf, wherein we define this set of resource types as a "recording_group" in the
            # "aws_config_delivery_channel"); we see these far too frequently to be worth alerting on - ignore...
            quit()
        elif "messageType" in message:
            # assume this is another type of AWS Config CloudWatch Event that we do not see so frequently...
            payload = config_cloudwatch_event_notification(message, region, payload)
        elif "AlarmName" in message:
            if os.environ["USE_AWS_SLACK_CHANNELS"].lower() == "true":
                payload = config_cloudwatch_alarm_notification(
                    message, region, os.environ["AWS_SLACK_CHANNEL_PROWLER"], payload
                )
            else:
                payload = config_prowler_cloudwatch_alarm_notification(
                    message, region, payload
                )
        else:
            payload = custom_notification(message, region, payload)

    if "blocks" in payload:
        payload["blocks"].insert(0, {"type": "divider"})
        payload["blocks"].append({"type": "divider"})

    dumped_payload = get_escaped_json_string(payload)
    logger.info(
        f'Parsed final slack payload", "payload": "{dumped_payload}", "slack_url": "{slack_url}", "correlation_id": "{correlation_id}'
    )

    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)
    urllib.request.urlopen(req, data)


def get_escaped_json_string(json_dict):
    serialized_json_dict = {
        k: v.isoformat() if type(v) is datetime else v for k, v in json_dict.items()
    }
    try:
        escaped_string = json.dumps(json.dumps(serialized_json_dict))
    except Exception:
        try:
            escaped_string = json.dumps(serialized_json_dict)
        except Exception:
            escaped_string = serialized_json_dict

    return escaped_string


def lambda_handler(event, context):
    # print(event)

    # note that, when calling the lambda function via the console 'test' button,
    # in order for the 'message' to not already be a 'dict', thus causing the 'loads' (str to dict) below to fail with error message
    # "the JSON object must be str, bytes or bytearray, not 'dict'", the double quotes in a message have to be escaped
    # & the message itself then placed within unescaped double quotes in the 'Amazon SNS Topic Notification' event template, ie:
    #         "Message": "example message",
    # becomes:
    #         "Message": "{\"AlarmName\": \"3.1 Unauthorized API calls\", ...

    dumped_event = get_escaped_json_string(event)
    logger.info(
        f'Processing event", "aws_event": {dumped_event}, "correlation_id": "{correlation_id}'
    )

    message = json.loads(event["Records"][0]["Sns"]["Message"])
    region = event["Records"][0]["Sns"]["TopicArn"].split(":")[3]

    dumped_message = get_escaped_json_string(message)
    logger.info(
        f'Parsed message", "dumped_message": {dumped_message}, "region": "{region}", "correlation_id": "{correlation_id}'
    )

    notify_slack(message, region)

    return message


if __name__ == "__main__":
    try:
        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )
        json_content = json.loads(open("event.json", "r").read())
        lambda_handler(json_content, None)
    except Exception as e:
        logger.error(e)
