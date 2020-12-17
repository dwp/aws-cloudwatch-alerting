#!/usr/bin/env python3

"""Tests for the AWS Cloudwatch Alerting Lambda."""
import json
import pytest
import unittest
import os
import mock
from datetime import datetime
from unittest.mock import MagicMock
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
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    def test_config_cloudwatch_alarm_notification_returns_prowler_config_when_prowler_namespace_present(
        self,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = { "Namespace": "Prowler/Monitoring" }

        (actual_slack_channel, actual_message) = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, 
            region, 
            slack_channel_main
        )

        prowler_cw_mock.assert_called_once_with(event, region)
        custom_cw_mock.assert_not_called()

        self.assertEqual(actual_slack_channel, slack_channel_main)


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_non_prowler_namespace_present(
        self,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = { "Namespace": "Test/Monitoring" }

        custom_cw_mock.return_value = (slack_channel_critical, { "Test": "test" })

        (actual_slack_channel, actual_message) = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, 
            region, 
            slack_channel_main
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region)

        self.assertEqual(actual_slack_channel, slack_channel_critical)


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_no_namespace_present(
        self,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = { "Test": "Test/Monitoring" }

        custom_cw_mock.return_value = (slack_channel_critical, { "Test": "test" })

        (actual_slack_channel, actual_message) = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, 
            region, 
            slack_channel_main
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region)

        self.assertEqual(actual_slack_channel, slack_channel_critical)


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_blank(
        self,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = { "Namespace": "" }

        custom_cw_mock.return_value = (slack_channel_critical, { "Test": "test" })

        (actual_slack_channel, actual_message) = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, 
            region, 
            slack_channel_main
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region)

        self.assertEqual(actual_slack_channel, slack_channel_critical)


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_prowler_cloudwatch_alarm_notification"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification"
    )
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_none(
        self,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = { "Namespace": None }

        custom_cw_mock.return_value = (slack_channel_critical, { "Test": "test" })

        (actual_slack_channel, actual_message) = aws_cloudwatch_alerting.config_cloudwatch_alarm_notification(
            event, 
            region, 
            slack_channel_main
        )

        prowler_cw_mock.assert_not_called()
        custom_cw_mock.assert_called_once_with(event, region)

        self.assertEqual(actual_slack_channel, slack_channel_critical)


    def test_get_tags_for_cloudwatch_alarm_calls_aws_correctly(
        self,
    ):
        cw_client = MagicMock()
        cw_client.list_tags_for_resource = MagicMock()

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm(
            cw_client,
            alarm_arn
        )

        cw_client.list_tags_for_resource.assert_called_once_with(ResourceARN=alarm_arn)


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_information(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "low",
            "information",
            "low",
            "information",
            ":information_source:",
            "good",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_information(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "medium",
            "information",
            "medium",
            "information",
            ":information_source:",
            "good",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_information(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "high",
            "information",
            "high",
            "information",
            ":information_source:",
            "good",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_information(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "information",
            "critical",
            "information",
            ":information_source:",
            "good",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "low",
            "warning",
            "low",
            "warning",
            ":warning:",
            "warning",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "medium",
            "warning",
            "medium",
            "warning",
            ":warning:",
            "warning",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "high",
            "warning",
            "high",
            "warning",
            ":warning:",
            "warning",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_warning(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "warning",
            "critical",
            "warning",
            ":warning:",
            "warning",
            slack_channel_critical,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_low_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "low",
            "error",
            "low",
            "error",
            ":fire:",
            "danger",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_medium_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "medium",
            "error",
            "medium",
            "error",
            ":fire:",
            "danger",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_high_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "high",
            "error",
            "high",
            "error",
            ":fire:",
            "danger",
            slack_channel_critical,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_right_values_for_critical_priority_error(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "critical",
            "error",
            "critical",
            "error",
            ":fire:",
            "danger",
            slack_channel_critical,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_no_tags(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            None,
            None,
            "NOT_SET",
            "NOT_SET",
            ":warning:",
            "warning",
            slack_channel_main,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_unrecognised_tags(
        self,
        tags_mock,
    ):
        custom_cloudwatch_alarm_notification_returns_right_values(
            self,
            tags_mock,
            "test",
            "test",
            "test",
            "test",
            ":warning:",
            "warning",
            slack_channel_main,
        )


    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_missing_tags(
        self,
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

        (
            actual_slack_channel,
            actual_attachment,
        ) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_attachment = {
            "color": "warning",
            "fallback": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "fields": [
                {
                    "title": "AWS Console link",
                    "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name",
                },
                {"title": "Trigger time", "value": state_updated_timestamp_string},
                {"title": "Severity", "value": "NOT_SET"},
                {"title": "Type", "value": "NOT_SET"},
            ],
        }
        self.assertEqual(actual_slack_channel, slack_channel_main)
        self.assertEqual(expected_attachment, actual_attachment)
        

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_blank_tags(
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
            {"Key": "severity", "Value": ""},
            {"Key": "notification_type", "Value": ""},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

        (
            actual_slack_channel,
            actual_attachment,
        ) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_attachment = {
            "color": "warning",
            "fallback": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "fields": [
                {
                    "title": "AWS Console link",
                    "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name",
                },
                {"title": "Trigger time", "value": state_updated_timestamp_string},
                {"title": "Severity", "value": "NOT_SET"},
                {"title": "Type", "value": "NOT_SET"},
            ],
        }
        self.assertEqual(actual_slack_channel, slack_channel_main)
        self.assertEqual(expected_attachment, actual_attachment)
        

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    def test_config_custom_cloudwatch_alarm_notification_returns_default_values_for_none_tags(
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
            {"Key": "severity", "Value": None},
            {"Key": "notification_type", "Value": None},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

        (
            actual_slack_channel,
            actual_attachment,
        ) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_attachment = {
            "color": "warning",
            "fallback": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "fields": [
                {
                    "title": "AWS Console link",
                    "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name",
                },
                {"title": "Trigger time", "value": state_updated_timestamp_string},
                {"title": "Severity", "value": "NOT_SET"},
                {"title": "Type", "value": "NOT_SET"},
            ],
        }
        self.assertEqual(actual_slack_channel, slack_channel_main)
        self.assertEqual(expected_attachment, actual_attachment)


def custom_cloudwatch_alarm_notification_returns_right_values(
    self,
    tags_mock,
    severity_tag,
    type_tag,
    expected_severity,
    expected_type,
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
        {"Key": "severity", "Value": severity_tag},
        {"Key": "notification_type", "Value": type_tag},
    ]

    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
    aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

    (
        actual_slack_channel,
        actual_attachment,
    ) = aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
        alarm, region
    )
    tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

    expected_attachment = {
        "color": expected_colour,
        "fallback": f'{expected_icon} *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
        "fields": [
            {
                "title": "AWS Console link",
                "value": "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name",
            },
            {"title": "Trigger time", "value": state_updated_timestamp_string},
            {"title": "Severity", "value": expected_severity},
            {"title": "Type", "value": expected_type},
        ],
    }
    self.assertEqual(actual_slack_channel, expected_slack_channel)
    self.assertEqual(expected_attachment, actual_attachment)


if __name__ == "__main__":
    unittest.main()
