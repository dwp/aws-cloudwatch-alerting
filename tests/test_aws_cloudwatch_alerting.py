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
test_namespace = "Test/Monitoring"
today = date.today()
now = datetime.now()
now_string = now.strftime("%H") + ":" + now.strftime("%M")
expected_cloudwatch_url = "https://console.aws.amazon.com/cloudwatch/home?region=eu-test-2#s=Alarms&alarm=test_alarm%20name"
state_updated_input_string = "2020-12-22T12:21:58.314+0000"
state_updated_output_string = "2020-12-22T12:21:58"
slack_channel_main = "test_slack_channel_main"
slack_channel_critical = "test_slack_channel_critical"
aws_environment = "test_environment"
test_title = "AWS DataWorks Service Alerts - test_environment"
aws_icon = ":aws:"

icon_information_source = ":information_source:"
icon_warning = ":warning:"
icon_fire = ":fire:"

unset_text = "NOT_SET"


@pytest.fixture(autouse=True)
def before():
    os.environ["AWS_SLACK_CHANNEL_MAIN"] = slack_channel_main
    os.environ["AWS_SLACK_CHANNEL_CRITICAL"] = slack_channel_critical
    os.environ["AWS_ENVIRONMENT"] = aws_environment
    os.environ["STATUS_SLACK_USERNAME"] = "test_username"


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
        event = {"Trigger": {"Namespace": "Prowler/Monitoring"}}
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
        event = {"Trigger": {"Namespace": test_namespace}}
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
        event = {"Trigger": {"Test_Namespace": test_namespace}}
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
        event = {"Trigger": {"Namespace": ""}}
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
        event = {"Trigger": {"Namespace": None}}
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_no_trigger_present(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Test_Trigger": {"Test_Namespace": test_namespace}}
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_trigger_blank(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Trigger": ""}
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
    def test_config_cloudwatch_alarm_notification_returns_custom_config_when_trigger_none(
        self,
        suppression_mock,
        custom_cw_mock,
        prowler_cw_mock,
    ):
        event = {"Trigger": None}
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
            unset_text,
            unset_text,
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
            unset_text,
            unset_text,
            unset_text,
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
            "StateChangeTime": state_updated_input_string,
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
            "username": f"AWS DataWorks Service Alerts - {aws_environment}",
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
                            "text": f"*{attachment_title_link_field}*: <{expected_cloudwatch_url}|Click here>",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_output_string}",
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
            "StateChangeTime": state_updated_input_string,
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
            "username": f"AWS DataWorks Service Alerts - {aws_environment}",
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
                            "text": f"*{attachment_title_link_field}*: <{expected_cloudwatch_url}|Click here>",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_output_string}",
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
            "StateChangeTime": state_updated_input_string,
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
            "username": f"AWS DataWorks Service Alerts - {aws_environment}",
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
                            "text": f"*{attachment_title_link_field}*: <{expected_cloudwatch_url}|Click here>",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_output_string}",
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
    def test_config_custom_cloudwatch_alarm_notification_returns_breakglass_values(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None
        breakglass_user = "test AWS Breakglass Alerts test"
        os.environ["STATUS_SLACK_USERNAME"] = breakglass_user

        alarm = {
            "AlarmName": alarm_name,
            "AlarmArn": alarm_arn,
            "StateChangeTime": state_updated_input_string,
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
                alarm, region, {"username": breakglass_user}
            )
        )
        tags_mock.assert_called_once_with(mock.ANY, alarm_arn)
        suppression_mock.assert_called_once_with(tags, mock.ANY, mock.ANY)

        expected_payload = {
            "username": f"AWS DataWorks Breakglass Alerts - {aws_environment}",
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
                            "text": f"*{attachment_title_link_field}*: <{expected_cloudwatch_url}|Click here>",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_output_string}",
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
    def test_config_custom_cloudwatch_alarm_notification_returns_security_finding_values(
        self,
        suppression_mock,
        tags_mock,
    ):
        self.maxDiff = None

        alarm = {
            "AlarmName": "Security Hub finding for tests",
            "AlarmArn": alarm_arn,
            "StateChangeTime": state_updated_input_string,
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

        expected_url = f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings?search=ComplianceStatus%3D%255Coperator%255C%253AEQUALS%255C%253AWARNING%26ComplianceStatus%3D%255Coperator%255C%253AEQUALS%255C%253AERROR"

        expected_payload = {
            "username": f"AWS DataWorks Security Hub Alerts - {aws_environment}",
            "channel": slack_channel_main,
            "icon_emoji": ":old_key:",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f'*TEST_ENVIRONMENT*: "_Security Hub finding for tests_" in eu-test-2',
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*{attachment_title_link_field}*: <{expected_url}|Click here>",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*{trigger_time_field_title}*: {state_updated_output_string}",
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
            "StateChangeTime": state_updated_input_string,
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
                "Value": f"Saturday+Wednesday+{today.strftime('%A')}",
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
                "Value": f"{(today + timedelta(days=1)).strftime('%A')}+{(today + timedelta(days=2)).strftime('%A')}",
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

    def test_alarm_is_not_suppressed_given_valid_time_outside_of_both_time_alert_tags(
        self,
    ):
        self.maxDiff = None

        before_time = now + timedelta(minutes=-2)
        before_string = before_time.strftime("%H") + ":" + before_time.strftime("%M")

        after_time = now + timedelta(minutes=2)
        after_string = after_time.strftime("%H") + ":" + after_time.strftime("%M")

        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": before_string,
            },
            {
                "Key": tag_key_do_not_alert_after,
                "Value": after_string,
            },
        ]

        expected_result = False
        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(tags, today, now)

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_time_earlier_with_both_time_alert_tags(
        self,
    ):
        self.maxDiff = None

        before_time = now + timedelta(minutes=-2)
        before_string = before_time.strftime("%H") + ":" + before_time.strftime("%M")

        after_time = now + timedelta(minutes=2)
        after_string = after_time.strftime("%H") + ":" + after_time.strftime("%M")

        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": before_string,
            },
            {
                "Key": tag_key_do_not_alert_after,
                "Value": after_string,
            },
        ]

        expected_result = True
        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=-5)
        )

        self.assertEqual(expected_result, actual_result)

    def test_alarm_is_suppressed_given_valid_time_later_with_both_time_alert_tags(
        self,
    ):
        self.maxDiff = None

        before_time = now + timedelta(minutes=-2)
        before_string = before_time.strftime("%H") + ":" + before_time.strftime("%M")

        after_time = now + timedelta(minutes=2)
        after_string = after_time.strftime("%H") + ":" + after_time.strftime("%M")

        tags = [
            {
                "Key": tag_key_do_not_alert_before,
                "Value": before_string,
            },
            {
                "Key": tag_key_do_not_alert_after,
                "Value": after_string,
            },
        ]

        expected_result = True
        actual_result = aws_cloudwatch_alerting.is_alarm_suppressed(
            tags, today, now + timedelta(minutes=5)
        )

        self.assertEqual(expected_result, actual_result)

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_alarm_notification_returns_right_values_when_all_defaults_used(
        self,
        suppression_mock,
        tags_mock,
    ):
        input_message = {}

        custom_alarm_notification_returns_right_values(
            self,
            suppression_mock,
            input_message,
            "Medium",
            "Warning",
            unset_text,
            unset_text,
            unset_text,
            icon_warning,
            slack_channel_main,
            unset_text,
            test_title,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_alarm_notification_returns_right_values_when_overrides_used(
        self,
        suppression_mock,
        tags_mock,
    ):
        input_message = {
            "icon_override": aws_icon,
            "slack_channel_override": "test-slack-channel-override",
        }

        custom_alarm_notification_returns_right_values(
            self,
            suppression_mock,
            input_message,
            "Medium",
            "Warning",
            unset_text,
            unset_text,
            unset_text,
            aws_icon,
            "test-slack-channel-override",
            unset_text,
            test_title,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_alarm_notification_returns_right_values_when_all_values_passed_in(
        self,
        suppression_mock,
        tags_mock,
    ):
        input_message = {
            "severity": "Low",
            "notification_type": "Information",
            "slack_username": "Test Alert",
            "active_days": "Monday",
            "do_not_alert_before": "0700",
            "do_not_alert_after": "1900",
            "icon_override": aws_icon,
            "slack_channel_override": "test-slack-channel-override",
            "log_with_here": "true",
            "title_text": "Test Title Text",
        }

        custom_alarm_notification_returns_right_values(
            self,
            suppression_mock,
            input_message,
            "Low",
            "Information",
            "Monday",
            "0700",
            "1900",
            aws_icon,
            "test-slack-channel-override",
            "Test Title Text",
            "Test Alert",
            True,
        )

    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.get_tags_for_cloudwatch_alarm"
    )
    @mock.patch(
        "aws_cloudwatch_alerting_lambda.aws_cloudwatch_alerting.is_alarm_suppressed"
    )
    def test_config_custom_alarm_notification_returns_right_values_with_custom_elements(
        self,
        suppression_mock,
        tags_mock,
    ):
        input_message = {
            "severity": "Low",
            "notification_type": "Information",
            "slack_username": "Test Alert",
            "active_days": "Monday",
            "do_not_alert_before": "0700",
            "do_not_alert_after": "1900",
            "icon_override": aws_icon,
            "slack_channel_override": "test-slack-channel-override",
            "log_with_here": "true",
            "title_text": "Test Title Text",
            "custom_elements": [
                {"key": "element_name_1", "value": "element_value_1"},
                {"key": "element_name_2", "value": "element_value_2"},
            ],
        }

        expected_custom_elements = [
            {
                "type": "mrkdwn",
                "text": f"*element_name_1*: element_value_1",
            },
            {
                "type": "mrkdwn",
                "text": f"*element_name_2*: element_value_2",
            },
        ]

        custom_alarm_notification_returns_right_values(
            self,
            suppression_mock,
            input_message,
            "Low",
            "Information",
            "Monday",
            "0700",
            "1900",
            aws_icon,
            "test-slack-channel-override",
            "Test Title Text",
            "Test Alert",
            True,
            expected_custom_elements,
        )


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
        "StateChangeTime": state_updated_input_string,
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

    expected_elements = []
    expected_types = [
        (attachment_title_link_field, f"<{expected_cloudwatch_url}|Click here>"),
        (trigger_time_field_title, state_updated_output_string),
        (severity_field_title, expected_severity),
        (type_field_title, expected_type),
        (active_days_field_title, expected_active_days),
        (skip_before_field_title, expected_skip_before),
        (skip_after_field_title, expected_skip_after),
    ]
    for expected_type_name, expected_type_value in expected_types:
        if expected_type_value != unset_text:
            expected_elements.append(
                {
                    "type": "mrkdwn",
                    "text": f"*{expected_type_name}*: {expected_type_value}",
                }
            )

    expected_payload = {
        "username": f"AWS DataWorks Service Alerts - {aws_environment}",
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
                "elements": expected_elements,
            },
        ],
    }

    self.assertEqual(expected_payload, actual_payload)


def custom_alarm_notification_returns_right_values(
    self,
    suppression_mock,
    input_message,
    expected_severity,
    expected_type,
    expected_active_days,
    expected_skip_before,
    expected_skip_after,
    expected_icon,
    expected_slack_channel,
    expected_title_text,
    expected_username,
    expected_here_tag=False,
    expected_custom_elements=None,
):
    self.maxDiff = None

    aws_cloudwatch_alerting.is_alarm_suppressed.return_value = False

    actual_payload = aws_cloudwatch_alerting.custom_notification(
        input_message, region, {}
    )
    suppression_mock.assert_called_once()

    expected_title = f'*TEST_ENVIRONMENT*: "_{expected_title_text}_" in eu-test-2'
    if expected_here_tag:
        expected_title = (
            f'@here *TEST_ENVIRONMENT*: "_{expected_title_text}_" in eu-test-2'
        )

    expected_elements = []
    expected_types = [
        (severity_field_title, expected_severity),
        (type_field_title, expected_type),
        (active_days_field_title, expected_active_days),
        (skip_before_field_title, expected_skip_before),
        (skip_after_field_title, expected_skip_after),
    ]
    for expected_type_name, expected_type_value in expected_types:
        if expected_type_value.lower() != unset_text.lower():
            expected_elements.append(
                {
                    "type": "mrkdwn",
                    "text": f"*{expected_type_name}*: {expected_type_value}",
                }
            )

    if expected_custom_elements is not None and len(expected_custom_elements) > 0:
        expected_elements.extend(expected_custom_elements)

    expected_payload = {
        "username": expected_username,
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
                "elements": expected_elements,
            },
        ],
    }

    self.assertEqual(expected_payload, actual_payload)


if __name__ == "__main__":
    unittest.main()
