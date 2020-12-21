#!/usr/bin/env python3

"""Tests for the AWS Cloudwatch Alerting Lambda."""
import json
import pytest
import unittest
import os
import mock
from datetime import datetime
from datetime import timedelta
from datetime import date
from unittest.mock import MagicMock
from aws_cloudwatch_alerting_lambda import aws_cloudwatch_alerting

region = "eu-test-2"
alarm_name = "test_alarm name"
alarm_arn = "test_alarm_arn"
attachment_title_link_field = "AWS Console link"
trigger_time_field_title = "Trigger time"
severity_field_title = "Severity"
type_field_title = "Type"
active_days_field_title = "Active days"
skip_before_field_title = "Suppress before"
skip_after_field_title = "Suppress after"
tag_key_severity = "severity"
tag_key_type = "notification_type"
tag_key_active_days = "active_days"
tag_key_do_not_alert_before = "do_not_alert_before"
tag_key_do_not_alert_after = "do_not_alert_after"
today = date.today()
now = datetime.now()
now_string = now.strftime("%H") + ":" + now.strftime("%M")
expected_cloudwatch_url = "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name"
state_updated_timestamp_string = "2019-12-01T13:04:03Z"
state_updated_datetime = datetime.strptime(
    state_updated_timestamp_string, "%Y-%m-%dT%H:%M:%SZ"
)
slack_channel_main = "test_slack_channel_main"
slack_channel_critical = "test_slack_channel_critical"
aws_environment = "test_environment"

os.environ["AWS_SLACK_CHANNEL_MAIN"] = slack_channel_main
os.environ["AWS_SLACK_CHANNEL_CRITICAL"] = slack_channel_critical
os.environ["AWS_ENVIRONMENT"] = aws_environment

icon_information_source = ":information_source:"
icon_warning = ":warning:"
icon_fire = ":fire:"


class TestRetriever(unittest.TestCase):
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_cloudwatch_alarm_notification_returns_prowler_config_when_prowler_namespace_present(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Namespace": "Prowler/Monitoring"}
        payload = {}
        return_payload = {"channel": slack_channel_main}

        prowler_cw_mock.return_value = return_payload

        actual_message = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, region, slack_channel_main, payload
        )

        prowler_cw_mock.assert_called_once_with(event, region, payload)
        custom_cw_mock.assert_not_called()

        self.assertEqual(actual_message["channel"], slack_channel_main)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_non_prowler_namespace_present(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Namespace": "Test/Monitoring"}
        payload = {}
        return_payload = {"channel": slack_channel_critical}

        custom_cw_mock.return_value = return_payload

        actual_message = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, region, slack_channel_main, payload
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region, payload)

        self.assertEqual(actual_message["channel"], slack_channel_critical)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_no_namespace_present(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Test": "Test/Monitoring"}
        payload = {}
        return_payload = {"channel": slack_channel_critical}

        custom_cw_mock.return_value = return_payload

        actual_message = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, region, slack_channel_main, payload
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region, payload)

        self.assertEqual(actual_message["channel"], slack_channel_critical)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_blank(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Namespace": ""}
        payload = {}
        return_payload = {"channel": slack_channel_critical}

        custom_cw_mock.return_value = return_payload

        actual_message = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, region, slack_channel_main, payload
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region, payload)

        self.assertEqual(actual_message["channel"], slack_channel_critical)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_none(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Namespace": None}
        payload = {}
        return_payload = {"channel": slack_channel_critical}

        custom_cw_mock.return_value = return_payload

        actual_message = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, region, slack_channel_main, payload
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region, payload)

        self.assertEqual(actual_message["channel"], slack_channel_critical)

    def test_get_tags_for_cloudwatch_alarm_calls_aws_correctly(
        self,
    ):
        cw_client = MagicMock()
        cw_client.list_tags_for_resource = MagicMock()

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm(cw_client, alarm_arn)

        cw_client.list_tags_for_resource.assert_called_once_with(ResourceARN=alarm_arn)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_information(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "low",
            "information",
            "low",
            "information",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_information_source,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_information(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "medium",
            "information",
            "medium",
            "information",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_information_source,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_information(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "high",
            "information",
            "high",
            "information",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_information_source,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_information(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "critical",
            "information",
            "critical",
            "information",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_information_source,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_warning(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "low",
            "warning",
            "low",
            "warning",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_warning(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "medium",
            "warning",
            "medium",
            "warning",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_warning(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "high",
            "warning",
            "high",
            "warning",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_warning(
        self,
        suppression_mock,
        tags_mock,
    ):
        os.environ["AWS_LOG_CRITICAL_WITH_HERE"] = ""

        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "critical",
            "warning",
            "critical",
            "warning",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_critical,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_error(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "low",
            "error",
            "low",
            "error",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_fire,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_error(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "medium",
            "error",
            "medium",
            "error",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_fire,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_error(
        self,
        suppression_mock,
        tags_mock,
    ):
        os.environ["AWS_LOG_CRITICAL_WITH_HERE"] = ""

        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "high",
            "error",
            "high",
            "error",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_fire,
            slack_channel_critical,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_error(
        self,
        suppression_mock,
        tags_mock,
    ):
        os.environ["AWS_LOG_CRITICAL_WITH_HERE"] = "true"

        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "critical",
            "error",
            "critical",
            "error",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_fire,
            slack_channel_critical,
            True,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_no_tags(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            None,
            None,
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_unrecognised_tags(
        self,
        suppression_mock,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            suppression_mock,
            "test",
            "test",
            "test",
            "test",
            "NOT_SET",
            "NOT_SET",
            "NOT_SET",
            icon_warning,
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_missing_tags(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateUpdatedTimestamp": state_updated_datetime,
        }

        tags = []

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags
        aws_cloudwatch_alerting.is_alarm_suppressed.return_value = False

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)
        suppression_mock.assert_called_once_with(tags, mock.ANY, mock.ANY)

        expected_payload = {
            "icon_emoji": ":warning:",
            "channel": slack_channel_main,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f'*TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{attachment_title_link_field}*: {expected_cloudwatch_url}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_timestamp_string}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{severity_field_title}*: NOT_SET",
                        },
                        {"type": "mrkdwn", "text": f"*{type_field_title}*: NOT_SET"},
                        {
                            "type": "mrkdwn",
                            "text": f"*{active_days_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_before_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_after_field_title}*: NOT_SET",
                        },
                    ],
                },
            ],
        }
        self.assertEqual(expected_payload, actual_payload)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_blank_tags(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateUpdatedTimestamp": state_updated_datetime,
        }

        tags = [
            {"Key": tag_key_severity, "Value": ""},
            {"Key": tag_key_type, "Value": ""},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags
        aws_cloudwatch_alerting.is_alarm_suppressed.return_value = False

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)
        suppression_mock.assert_called_once_with(tags, mock.ANY, mock.ANY)

        expected_payload = {
            "icon_emoji": ":warning:",
            "channel": slack_channel_main,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f'*TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{attachment_title_link_field}*: {expected_cloudwatch_url}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_timestamp_string}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{severity_field_title}*: NOT_SET",
                        },
                        {"type": "mrkdwn", "text": f"*{type_field_title}*: NOT_SET"},
                        {
                            "type": "mrkdwn",
                            "text": f"*{active_days_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_before_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_after_field_title}*: NOT_SET",
                        },
                    ],
                },
            ],
        }
        self.assertEqual(expected_payload, actual_payload)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_none_tags(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateUpdatedTimestamp": state_updated_datetime,
        }

        tags = [
            {"Key": tag_key_severity, "Value": None},
            {"Key": tag_key_type, "Value": None},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags
        aws_cloudwatch_alerting.is_alarm_suppressed.return_value = False

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)
        suppression_mock.assert_called_once_with(tags, mock.ANY, mock.ANY)

        expected_payload = {
            "icon_emoji": ":warning:",
            "channel": slack_channel_main,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f'*TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{attachment_title_link_field}*: {expected_cloudwatch_url}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_timestamp_string}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{severity_field_title}*: NOT_SET",
                        },
                        {"type": "mrkdwn", "text": f"*{type_field_title}*: NOT_SET"},
                        {
                            "type": "mrkdwn",
                            "text": f"*{active_days_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_before_field_title}*: NOT_SET",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{skip_after_field_title}*: NOT_SET",
                        },
                    ],
                },
            ],
        }
        self.assertEqual(expected_payload, actual_payload)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_cloudwatch_alarm_notification_exits_when_suppressed(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateUpdatedTimestamp": state_updated_datetime,
        }

        tags = [
            {"Key": tag_key_severity, "Value": None},
            {"Key": tag_key_type, "Value": None},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags
        aws_cloudwatch_alerting.is_alarm_suppressed.return_value = True

        with pytest.raises(SystemExit) as pytest_wrapped_e:
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )

        self.assertEqual(0, pytest_wrapped_e.value.code)
        self.assertEqual(SystemExit, pytest_wrapped_e.type)

    def test_alarm_is_not_suppressed_given_no_tags(
        self,
    ):
        self.maxDiff = None
        tags = []
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_none_tags(
        self,
    ):
        self.maxDiff = None
        tags = None
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_unrecognised_tags(
        self,
    ):
        self.maxDiff = None
        tags = [
            {"Key": tag_key_severity, "Value": None},
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_days_tag_with_one_day(
        self,
    ):
        self.maxDiff = None
        tags = [
            {"Key": tag_key_active_days, "Value": today.strftime("%A")},
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_days_tag_with_multiple_days(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_active_days,
                "Value": f"Saturday,Wednesday,{today.strftime('%A')}",
            },
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_days_tag_regardless_of_case(
        self,
    ):
        self.maxDiff = None
        tags = [
            {"Key": tag_key_active_days, "Value": today.strftime("%A").upper()},
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_days_without_today_with_one_day(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_active_days,
                "Value": (today + timedelta(days=1)).strftime("%A"),
            },
        ]
        expected_result = True

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_days_without_today_regardless_of_case(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_active_days,
                "Value": (today + timedelta(days=1)).strftime("%A").upper(),
            },
        ]
        expected_result = True

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_days_without_today_with_multiple_days(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_active_days,
                "Value": f"{(today + timedelta(days=1)).strftime('%A')},{(today + timedelta(days=2)).strftime('%A')}",
            },
        ]
        expected_result = True

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_time_later_than_now_do_not_alert_before_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": now_string,
            },
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=1)
        )

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_time_matching_than_now_do_not_alert_before_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": now_string,
            },
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_time_earlier_than_now_do_not_alert_before_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": now_string,
            },
        ]
        expected_result = True

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=-1)
        )

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_time_later_than_now_do_not_alert_after_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_after,
                "Value": now_string,
            },
        ]
        expected_result = True

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=1)
        )

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_time_matching_than_now_do_not_alert_after_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_after,
                "Value": now_string,
            },
        ]
        expected_result = False

        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_not_suppressed_given_valid_time_earlier_than_now_do_not_alert_after_time(
        self,
    ):
        self.maxDiff = None
        tags = [
            {
                "Key": tag_key_do_not_alert_after,
                "Value": now_string,
            },
        ]

        expected_result = False
        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=-1)
        )

        self.assertEqual(expected_result, actual_result)


def custom_cloudwatch_alarm_notification_returns_right_values(
    self,
    tags_mock,
    suppression_mock,
    severity_tag,
    type_tag,
    expected_severity,
    expected_type,
    expected_active_days,
    expected_skip_before,
    expected_skip_after,
    expected_icon,
    expected_slack_channel,
    expected_here_tag=False,
):
    self.maxDiff = None

    alarm = {
        "AlarmName": alarm_name,
        "AlarmArn": alarm_arn,
        "StateUpdatedTimestamp": state_updated_datetime,
    }

    tags = [
        {"Key": tag_key_severity, "Value": severity_tag},
        {"Key": tag_key_type, "Value": type_tag},
    ]

    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags
    aws_cloudwatch_alerting.is_alarm_suppressed.return_value = False

    actual_payload = (
        aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region, {}
        )
    )
    tags_mock.assert_called_once_with(mock.ANY, alarm_arn)
    suppression_mock.assert_called_once_with(tags, mock.ANY, mock.ANY)

    expected_title = '*TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2'
    if expected_here_tag:
        expected_title = '@here *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2'

    expected_payload = {
        "icon_emoji": expected_icon,
        "channel": expected_slack_channel,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": expected_title,
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*{attachment_title_link_field}*: {expected_cloudwatch_url}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{trigger_time_field_title}*: {state_updated_timestamp_string}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{severity_field_title}*: {expected_severity}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{type_field_title}*: {expected_type}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{active_days_field_title}*: {expected_active_days}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{skip_before_field_title}*: {expected_skip_before}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*{skip_after_field_title}*: {expected_skip_after}",
                    },
                ],
            },
        ],
    }

    self.assertEqual(expected_payload, actual_payload)


if __name__ == "__main__":
    unittest.main()
