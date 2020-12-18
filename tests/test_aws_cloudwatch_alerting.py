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
attachment_title_link_field = "AWS Console link"
trigger_time_field_title = "Trigger time"
severity_field_title = "Severity"
type_field_title = "Type"
tag_key_severity = "severity"
tag_key_type = "notification_type"
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
    def test_config_cloudwatch_alarm_notification_returns_prowler_config_when_prowler_namespace_present(
        self,
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_non_prowler_namespace_present(
        self,
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_no_namespace_present(
        self,
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_blank(
        self,
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_namespace_none(
        self,
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
            icon_information_source,
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
            icon_information_source,
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
            icon_information_source,
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
            icon_information_source,
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
            icon_warning,
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
            icon_warning,
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
            icon_warning,
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
            icon_warning,
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
            icon_fire,
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
            icon_fire,
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
            icon_fire,
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
            icon_fire,
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
            icon_warning,
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
            icon_warning,
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

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_payload = {
            "channel": slack_channel_main,
            "text": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "fields": [
                            {
                                "title": attachment_title_link_field,
                                "value": expected_cloudwatch_url,
                            },
                            {
                                "title": trigger_time_field_title,
                                "value": state_updated_timestamp_string,
                            },
                            {"title": severity_field_title, "value": "NOT_SET"},
                            {"title": type_field_title, "value": "NOT_SET"},
                        ],
                    },
                }
            ],
        }
        self.assertEqual(expected_payload, actual_payload)

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
            {"Key": tag_key_severity, "Value": ""},
            {"Key": tag_key_type, "Value": ""},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_payload = {
            "channel": slack_channel_main,
            "text": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "fields": [
                            {
                                "title": attachment_title_link_field,
                                "value": expected_cloudwatch_url,
                            },
                            {
                                "title": trigger_time_field_title,
                                "value": state_updated_timestamp_string,
                            },
                            {"title": severity_field_title, "value": "NOT_SET"},
                            {"title": type_field_title, "value": "NOT_SET"},
                        ],
                    },
                }
            ],
        }
        self.assertEqual(expected_payload, actual_payload)

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
            {"Key": tag_key_severity, "Value": None},
            {"Key": tag_key_type, "Value": None},
        ]

        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm = tags_mock
        aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm.return_value = tags

        actual_payload = (
            aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
                alarm, region, {}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

        expected_payload = {
            "channel": slack_channel_main,
            "text": f':warning: *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "fields": [
                            {
                                "title": attachment_title_link_field,
                                "value": expected_cloudwatch_url,
                            },
                            {
                                "title": trigger_time_field_title,
                                "value": state_updated_timestamp_string,
                            },
                            {"title": severity_field_title, "value": "NOT_SET"},
                            {"title": type_field_title, "value": "NOT_SET"},
                        ],
                    },
                }
            ],
        }
        self.assertEqual(expected_payload, actual_payload)


def custom_cloudwatch_alarm_notification_returns_right_values(
    self,
    tags_mock,
    severity_tag,
    type_tag,
    expected_severity,
    expected_type,
    expected_icon,
    expected_slack_channel,
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

    actual_payload = (
        aws_cloudwatch_alerting.config_custom_cloudwatch_alarm_notification(
            alarm, region, {}
        )
    )
    tags_mock.assert_called_once_with(mock.ANY, alarm_arn)

    expected_payload = {
        "channel": expected_slack_channel,
        "text": f'{expected_icon} *TEST_ENVIRONMENT*: "_test_alarm name_" in eu-test-2',
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "fields": [
                        {
                            "title": attachment_title_link_field,
                            "value": expected_cloudwatch_url,
                        },
                        {
                            "title": trigger_time_field_title,
                            "value": state_updated_timestamp_string,
                        },
                        {"title": severity_field_title, "value": expected_severity},
                        {"title": type_field_title, "value": expected_type},
                    ],
                },
            }
        ],
    }

    self.assertEqual(expected_payload, actual_payload)


if __name__ == "__main__":
    unittest.main()
