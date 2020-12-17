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
        self.maxDiff = None

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateUpdatedTimestamp": state_updated_datetime,
        }

        tags = [
            {"Key": "severity", "Value": "high"},
            {"Key": "notification_type", "Value": "information"},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

        (
            actual_slack_channel,
            actual_attachment,
        ) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region
        )
        tags_mock.assert_called_once_with(alarm_arn)

        expected_attachment = {
            "color": "good",
            "fallback": ':information_source: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "fields": [
                {
                    "title": "AWS Console link",
                    "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name",
                },
                {"title": "Trigger time", "value": state_updated_timestamp_string},
                {"title": "Severity", "value": "high"},
                {"title": "Type", "value": "information"},
            ],
        }
        self.assertEqual(actual_slack_channel, slack_channel_main)
        self.assertEqual(expected_attachment, actual_attachment)


if __name__ == "__main__":
    unittest.main()
