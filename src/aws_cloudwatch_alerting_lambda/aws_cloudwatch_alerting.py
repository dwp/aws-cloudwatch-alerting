# Based on:
# https://raw.githubusercontent.com/terraform-aws-modules/terraform-aws-notify-slack/659b4aac4aee2ab026d9f117f52a90cfc7ae0cff/functions/notify_slack.py
# installed by script
from __future__ import print_function
import os, boto3, json, base64
import urllib.request, urllib.parse
import logging
from datetime import datetime
from datetime import timedelta

# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ["AWS_REGION"]
    try:
        kms = boto3.client("kms", region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))[
            "Plaintext"
        ]
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")


def config_notification(message, region):
    states = {"COMPLIANT": "good", "NOT_APPLICABLE": "good", "NON_COMPLIANT": "danger"}
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
        "https://"
        + region
        + ".console.aws.amazon.com/config/home#/rules/rule-details/"
        + urllib.parse.quote_plus(
            message["newEvaluationResult"]["evaluationResultIdentifier"][
                "evaluationResultQualifier"
            ]["configRuleName"]
        )
    )

    return {
        "color": states[message["newEvaluationResult"]["complianceType"]],
        "fallback": "AWS Config Compliance Change detected " + config_rule_name,
        "fields": [
            {
                "title": "AWS Config Compliance Rule [" + config_rule_name + "]",
                "value": " has changed from ["
                + no_emojis[config_old_state]
                + "] to ["
                + emojis[config_new_state]
                + "]\nThis script can't tell if everything is compliant or not. For full details check the AWS Console: "
                + config_url,
            }
        ],
    }


def config_cloudwatch_event_notification(message, region):
    # see: https://docs.aws.amazon.com/config/latest/developerguide/monitor-config-with-cloudwatchevents.html
    # see also: https://docs.aws.amazon.com/config/latest/developerguide/example-sns-notification.html
    title = "AWS Config CloudWatch Event."
    value = "Unidentified"
    config_url = (
        "https://"
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
            "https://"
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
        return default_notification(message)

    return {
        "fallback": title,
        "fields": [
            {
                "title": title,
                "value": value
                + "\nFor full details check the AWS Console ["
                + config_url
                + "].",
            }
        ],
    }


def config_cloudwatch_alarm_notification(message, region, prowler_slack_channel):
    return (
        (
            prowler_slack_channel,
            config_prowler_cloudwatch_alarm_notification(message, region),
        )
        if "Namespace" in message and message["Namespace"] == "Prowler/Monitoring"
        else config_custom_cloudwatch_alarm_notification(message, region)
    )


def get_tags_for_cloudwatch_alarm(alarm_arn):
    cw_client = boto3.client("cloudwatch")
    return cw_client.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]


def config_custom_cloudwatch_alarm_notification(message, region):
    slack_channel_main = os.environ["AWS_SLACK_CHANNEL_MAIN"]
    slack_channel_critical = os.environ["AWS_SLACK_CHANNEL_CRITICAL"]
    environment_name = os.environ["AWS_ENVIRONMENT"]

    alarm_name = message["AlarmName"]

    cw_client = boto3.client("cloudwatch")
    tags = get_tags_for_cloudwatch_alarm(message["AlarmArn"])
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

    alarm_url = (
        "https://console.aws.amazon.com/cloudwatch/home?region="
        + region
        + "#s=Alarms&alarm="
        + alarm_name.replace(" ", "%20")
    )

    colour = "warning"
    icon = ":warning:"
    slack_channel = slack_channel_main

    if notification_type.lower() == "information":
        icon = ":information_source:"
        colour = "good"
    elif notification_type.lower() == "error":
        icon = ":fire:"
        colour = "danger"
        if severity.lower() == "high" or severity.lower() == "critical":
            slack_channel = slack_channel_critical
    elif severity.lower() == "critical":
        slack_channel = slack_channel_critical

    title = f'{icon} *{environment_name.upper()}*: "_{alarm_name}_" in {region}'

    return (
        slack_channel,
        {
            "color": colour,
            "fallback": title,
            "fields": [
                {"title": "AWS Console link", "value": alarm_url},
                {
                    "title": "Trigger time",
                    "value": message["StateUpdatedTimestamp"].strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                },
                {"title": "Severity", "value": severity},
                {"title": "Type", "value": notification_type},
            ],
        },
    )


def config_prowler_cloudwatch_alarm_notification(message, region):
    # See matching patterns at: https://github.com/dwp/terraform-aws-prowler-monitoring/blob/master/main.tf
    cloudwatch_metric_filters = {
        #'3.1 Unauthorized API calls': '?UnauthorizedOperation ?AccessDenied',
        "3.1 Unauthorized API calls": '{($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")}',
        "3.2 Management Console sign-in without MFA": '{$.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No"}',
        "3.3 usage of root account": '{$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent"}',
        "3.4 IAM policy changes": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
        "3.5 CloudTrail configuration changes": "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}",
        "3.6 AWS Management Console authentication failures": '{($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication")}',
        "3.7 disabling or scheduled deletion of customer created CMKs": "{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}",
        "3.8 S3 bucket policy changes": "{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication))}",
        "3.9 AWS Config configuration changes": "{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}",
        "3.10 security group changes": "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}",
        "3.11 changes to Network Access Control Lists (NACL)": "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}",
        "3.12 changes to network gateways": "{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)}",
        "3.13 route table changes": "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}",
        "3.14 VPC changes": "{($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink)}",
    }

    title = "AWS CloudWatch Alarm."
    alarm_name = message["AlarmName"]

    # providing a link back to the alarm is not of much use...
    alarm_url = (
        "https://console.aws.amazon.com/cloudwatch/home?region="
        + region
        + "#s=Alarms&alarm="
        + alarm_name.replace(" ", "%20")
    )
    url_to_use = alarm_url

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
    trigger_namespace = message["Trigger"]["Namespace"]
    value = (
        "["
        + trigger_namespace
        + "] alarm ["
        + alarm_name
        + "] triggered at ["
        + cloudwatch_logs_search_end_datetime_object.strftime("%Y-%m-%dT%H:%M:%SZ")
        + "]."
    )

    aws_account_id = message["AWSAccountId"]
    # log_group = "smimonitoring-dev-prowler-monitoring-logs"
    cloudwatch_log_group = os.environ["CLOUDWATCH_LOG_GROUP_NAME"]
    cloudwatch_log_stream = aws_account_id + "_CloudTrail_" + region
    cloudwatch_metric_filter = ""

    if alarm_name in cloudwatch_metric_filters:
        cloudwatch_metric_filter = cloudwatch_metric_filters[alarm_name]

    cloudwatch_metric_filter = cloudwatch_metric_filter.replace(" ", "%20")
    cloudwatch_metric_filter = cloudwatch_metric_filter.replace("=", "%3D")

    cloudwatch_log_url = (
        "https://console.aws.amazon.com/cloudwatch/home?region="
        + region
        + "#logEventViewer:group="
        + cloudwatch_log_group
        + ";stream="
        + cloudwatch_log_stream
        + ";filter="
        + cloudwatch_metric_filter
        + ";start="
        + cloudwatch_logs_search_start_datetime_object.strftime("%Y-%m-%dT%H:%M:%SZ")
        + ";end="
        + cloudwatch_logs_search_end_datetime_object.strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    url_to_use = cloudwatch_log_url

    return {
        "color": "danger",
        "fallback": title,
        "fields": [
            {
                "title": title,
                "value": value
                + " For full details check the AWS Console ["
                + url_to_use
                + "].",
            }
        ],
    }


def guardduty_notification(message, region):
    gd_finding_detail_type = message["detail"]["type"]
    gd_finding_detail_service_action_type = message["detail"]["service"]["action"][
        "actionType"
    ]
    gd_finding_detail_resource_type = message["detail"]["resource"]["resourceType"]
    gd_url = (
        "https://"
        + region
        + ".console.aws.amazon.com/guardduty/home?region="
        + region
        + "#/findings"
    )

    return {
        "color": "danger",
        "fallback": "AWS GuardDuty Finding Type [" + gd_finding_detail_type + "]",
        "fields": [
            {
                "title": "AWS GuardDuty Finding.",
                "value": "Finding of type ["
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
    }


def app_notification(slack_message, region):
    states = {"INFO": "good", "ERROR": "danger"}

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

    return {
        "color": states[app_function_message_type],
        "fallback": title,
        "fields": [
            {
                "title": title,
                "value": app_function
                + " "
                + app_function_message_type
                + ": "
                + app_function_message,
            }
        ],
    }


def default_notification(message):
    return {
        "fallback": "A new message",
        "fields": [{"title": "Message", "value": json.dumps(message), "short": False}],
    }


# Send a message to a slack channel
def notify_slack(message, region):

    if "slack" in message:
        # this is some info from one of our apps, intended for an app-specific slack channel...

        slack_url = os.environ["APP_INFO_SLACK_WEBHOOK_URL"]
        if not slack_url.startswith("http"):
            slack_url = decrypt(slack_url)

        slack_channel = os.environ["APP_INFO_SLACK_CHANNEL"]
        slack_username = os.environ["APP_INFO_SLACK_USERNAME"]

        payload = {
            "channel": slack_channel,
            "username": slack_username,
            "attachments": [],
        }

        payload["attachments"].append(app_notification(message, region))
    else:
        # this is a status update from AWS...

        slack_url = os.environ["STATUS_SLACK_WEBHOOK_URL"]

        if not slack_url.startswith("http"):
            slack_url = decrypt(slack_url)

        slack_channel = os.environ["STATUS_SLACK_CHANNEL"]
        slack_username = os.environ["STATUS_SLACK_USERNAME"]

        payload = {
            "channel": slack_channel,
            "username": slack_username,
            "attachments": [],
        }

        if "detail-type" in message and message["detail-type"] == "GuardDuty Finding":
            payload["attachments"].append(guardduty_notification(message, region))
        elif "configRuleName" in message:
            # this is a compliance/non-compliance AWS Config message...
            payload["attachments"].append(config_notification(message, region))
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
            payload["attachments"].append(
                config_cloudwatch_event_notification(message, region)
            )
        elif "AlarmName" in message:
            # this is a CloudWatch Alarm; assume it is from prowler monitoring...
            (channel, attachment) = config_cloudwatch_alarm_notification(
                message, region, slack_channel
            )
            payload["channel"] = channel
            payload["attachments"].append(attachment)
        else:
            payload["text"] = "Unidentified notification"
            payload["attachments"].append(default_notification(message))

    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)
    urllib.request.urlopen(req, data)


def handler(event, context):
    # print(event)

    # note that, when calling the lambda function via the console 'test' button,
    # in order for the 'message' to not already be a 'dict', thus causing the 'loads' (str to dict) below to fail with error message
    # "the JSON object must be str, bytes or bytearray, not 'dict'", the double quotes in a message have to be escaped
    # & the message itself then placed within unescaped double quotes in the 'Amazon SNS Topic Notification' event template, ie:
    #         "Message": "example message",
    # becomes:
    #         "Message": "{\"AlarmName\": \"3.1 Unauthorized API calls\", ...

    message = json.loads(event["Records"][0]["Sns"]["Message"])
    region = event["Records"][0]["Sns"]["TopicArn"].split(":")[3]

    print(message)
    notify_slack(message, region)

    return message


if __name__ == "__main__":
    try:
        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )
        json_content = json.loads(open("event.json", "r").read())
        handler(json_content, None)
    except Exception as e:
        logger.error(e)
