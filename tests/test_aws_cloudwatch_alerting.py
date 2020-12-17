#!/usr/bin/env python3

"""Tests for the AWS Cloudwatch Alerting Lambda."""
import json
import pytest
import unittest
import os
import mock
from datetime import datetime
from aws_cloudwatch_alerting_lambda import aws_cloudwatch_alerting

region = "eu-test-2"
alarm_name = "test_alarm name"
alarm_arn = "test_alarm_arn"
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


class TestRetriever(unittest.TestCase):
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_information(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "information",
            ":information_source:",
            "good",
            slack_channel_main,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "low",
            "warning",
            ":warning:",
            "warning",
            slack_channel_main,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "high",
            "warning",
            ":warning:",
            "warning",
            slack_channel_main,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "warning",
            ":warning:",
            "warning",
            slack_channel_critical,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "low",
            "error",
            ":fire:",
            "danger",
            slack_channel_main,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "high",
            "error",
            ":fire:",
            "danger",
            slack_channel_critical,
        )


    @mock.patch("aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm")
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "error",
            ":fire:",
            "danger",
            slack_channel_critical,
        )

def custom_cloudwatch_alarm_notification_returns_right_values(
    self,
    tags_mock,
    severity_tag,
    type_tag,
    expected_icon,
    expected_colour,
    expected_slack_channel,
):
    self.maxDiff = None

    alarm = {
        "AlarmName": alarm_name,
        "AlarmArn": alarm_arn,
        "StateUpdatedTimestamp": state_updated_datetime,
    }

    tags = [
        {
            'Key': 'severity',
            'Value': severity_tag
        },
        {
            'Key': 'notification_type',
            'Value': type_tag
        },
    ]

    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

    (actual_slack_channel, actual_attachment) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(alarm, region)
    tags_mock.assert_called_once_with(alarm_arn)

    expected_attachment = {
        "color": expected_colour,
        "fallback": f"{expected_icon} *TEST_ENVIRONMENT*: \"_test_alarm name_\" in eu-test-2",
        "fields": [
            {
                "title": "AWS Console link",
                "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name"
            },
            {
                "title": "Trigger time",
                "value": state_updated_timestamp_string
            },
            {
                "title": "Severity",
                "value": severity_tag
            },
            {
                "title": "Type",
                "value": type_tag
            }
        ],
    }
    self.assertEqual(actual_slack_channel, expected_slack_channel)
    self.assertEqual(expected_attachment, actual_attachment)

if __name__ == "__main__":
    unittest.main()
