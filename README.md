# DO NOT USE THIS REPO - MIGRATED TO GITLAB

# aws-cloudwatch-alerting
Lambda function to send CloudWatch alerts to Slack written in python 3.8

## Basic functionality

The lambda reacts to given SNS messages, looks at the payload and generates a slack message payload which it then posts to a slack webhook URL.

## Message structure

The lambda will react to alerts sent from SNS to whatever topics it is subscribed to. The SNS message structure can be found at https://docs.aws.amazon.com/lambda/latest/dg/with-sns.html.

## Different message types

The app will look at the message payload (`$.Records[0].SNS.Message`) and react differently depending on different fields that are present. These scenarios are desribed below.

If none of these scenarios are matched, then there is a fallback scenario which will which send a message with the phrase `Unidentified message` as the title the dumped payload as well.

### App notifications

App notifications are classified by a message which has the top level field of `slack` in their payload. An app notification looks in the payload and picks out the following fields to format its slack message:

* `$.application`
* `$.function`
* `$.messageType`
* `$.message`

The application is checked against a recognised list and if the app is recognised a message is sent to slack with the values for the other fields above.

The list of recognised apps is:

* `Security`
* `Payment`
* `Pipeline`
* `TransferToPensionAge`
* `MI12CaseControl`
* `QLR`
* `ReleaseComparison`

### Guard duty notifications

If the message has the `detail-type` field and the field contains `GuardDuty Finding` it is a guard duty notification. If this is the case then a notification is logged with the text `AWS GuardDuty Finding Type` and a URL is constructed to go directly to the finding in the AWS console.

### Configuration notifications

If the message has the `configRuleName` field it is a configuration notification. If this is the case then a notification is logged with the text `AWS Config Compliance Change detected` and a URL is constructed to go directly to the finding in the AWS console.

### Cloudwatch event notifications

If the message has the `messageType` field it is a cloudwatch event notification. If this is the case then a notification is logged with the text `AWS Config CloudWatch Event` and a URL is constructed to go directly to the finding in the AWS console. Details of the event are pulled out and provided as extra information in the slack message.

### Cloudwatch alarm notifications

If the message has the `AlarmName` field it is a cloudwatch alarm notification. If this is the case their are two sub scenarios based on the message itself.

#### Prowler alarms

If the message has the `Namespace` field and its value is set to `Prowler/Monitoring` then the message is assumed to be from the Prowler monitoring that is set up. In this case, the message is processed with a title of the name of the monitoring alert triggered and a URL to go to the alert directly is generated and set in the slack message.

#### Custom cloudwatch alarms

Without the `Namespace` field or if it is set to a different value, then the message is treated differently. The title will be set as the following:

* `{icon} *{environment_name.upper()}*: "_{alarm_name}_" in {region}'`

The `region` and `alarm_name` fields come directly from the message and `environment_name` is from the `AWS_ENVIRONMENT_NAME` environment variable.

The icon is set from the severity and the type of notification. These values also set the channel that the slack notification goes to and they are logged in the message as well. Their values are retrieved from the tags on the cloudwatch alarm itself and are detailed in the section below.

#### Custom alarm tags

The following tags are retrieved from the cloudwatch alarm and each one has a default in case it is not present:

* `severity` -> a combination of this and `notification_type` are used to determine the icon used for the alarm and the channel it goes to (see `Environment variables` section for details), supported values are `Low`, `Medium`, `High` and `Critical`. Default is `Medium`

* `notification_type` -> a combination of this and `severity` are used to determine the icon used for the alarm and the channel it goes to (see `Environment variables` section for details), supported values are `Information`, `Warning` and `Error`. Default is `Warning`

* `active_days` -> if set, this will mean any alarm on a day that is not present in this list will be suppressed and no notification will be sent to slack. The format is a `+` delimited list of ini-capped weekday names, i.e. `Monday+Tuesday`. Default is `NOT_SET`

* `do_not_alert_before` -> if set, this will mean any alarm which is triggered before the given time will be suppressed and no notification will be sent to slack. The format supported is `HH:MM` or `HHMM`. Default is `NOT_SET`

* `do_not_alert_after` -> if set, this will mean any alarm which is triggered after the given time will be suppressed and no notification will be sent to slack. The format supported is `HH:MM` or `HHMM`. Default is `NOT_SET`

## Environment variables

The following variables are supported when using this app:

* `LOG_LEVEL` (optional) -> The level to log at, can be `DEBUG`, `INFO` or `ERROR` and default is `INFO`
* `AWS_PROFILE` (optional) -> The AWS profile to use for AWS connections, defaults to `default`
* `AWS_REGION` (optional) -> The AWS region to use for AWS connections, defaults to `eu-west-2`
* `ENVIRONMENT` (optional) -> The readable name of the environment
* `APPLICATION` (optional) -> The readable name of the application
* `USE_AWS_SLACK_CHANNELS` (optional) -> Used to denote if AWS slack channel variables are to be used for alarm type notications (see above, this refers to both Prowler and Custom) -> this is provided so that current users of the app are not affected by changes but other AWS users can use different channel options. Format is `true` or `false` and default is `false`.

If `USE_AWS_SLACK_CHANNELS` is set to `true` then the following variables must also be provided.

* `AWS_SLACK_CHANNEL_MAIN` (required if `USE_AWS_SLACK_CHANNELS` is `true`) -> The slack channel to send all Prowler messages, custom `Information` notifications, custom `Warning` notifications that are not `Critical` severity and custom `Error` notifications that are not `High` or `Critical` severity
* `AWS_SLACK_CHANNEL_CRITICAL` (required if `USE_AWS_SLACK_CHANNELS` is `true`) -> The slack channel to send all custom `Warning` notifications that are `Critical` severity and custom `Error` notifications that are `High` or `Critical` severity
* `AWS_SLACK_CHANNEL_NOTIFICATIONS` (optional) -> Where all information messages will be sent to, if not provided uses the main slack channel var
* `AWS_SLACK_CHANNEL_PROWLER` (required if `USE_AWS_SLACK_CHANNELS` is `true`) -> Where all prowler messages will be sent to
* `AWS_ENVIRONMENT` (required if `USE_AWS_SLACK_CHANNELS` is `true`) -> The environment name the AWS alarms will be coming from, should be a human readable name
* `AWS_LOG_CRITICAL_WITH_HERE` (optional) -> If passed as `true` then a `@here` is added to notifications sent to `AWS_SLACK_CHANNEL_CRITICAL`

If this application is going to be used to receive anything other than `app` or `custom cloudwatch alarm` notification types (see above) then the following must also be provided for it to work

* `STATUS_SLACK_WEBHOOK_URL` (required if non app/custom alarm notications needed) -> The slack URL to send these notifications to
* `STATUS_SLACK_CHANNEL` (required if non app/custom alarm notications needed) -> The name of the slack channel to send these notifications to
* `STATUS_SLACK_USERNAME` (required if non app/custom alarm notications needed) -> The username used for posting these notifications, can be anything
* `STATUS_SLACK_ICON_EMOJI` (optional) -> The icon name used for these notifications, defaults to `:aws:`

If this application is going to be used to receive `app` notification types (see above) then the following must be provided for it to work

* `APP_INFO_SLACK_WEBHOOK_URL` (required if app notications needed) -> The slack URL to send app notifications to
* `APP_INFO_SLACK_CHANNEL` (required if app notications needed) -> The name of the slack channel to send app notifications to
* `APP_INFO_SLACK_USERNAME` (required if app notications needed) -> The username used for posting app notifications, can be anything
* `APP_INFO_SLACK_ICON_EMOJI` (optional) -> The icon name used for app notifications, defaults to `:aws:`

### Custom notifications

If the message doesn't meet any of the conditions to be one of the types above, then it is treated as a custom notification. This enables anyone to log notifications with the right message to the SQS queues that are subscribed by this lambda. The following is an example message to send where the values describe what they can be:

```
{
    "severity": "Critical" #Can be Critical, High, Medium or Low and defaults to "Medium"
    "notification_type": "Error" #Can be Error, Warning or Information and defaults to Warning
    "slack_username": "PDM Alerts" #Username for slack message and defaults to "AWS DataWorks Service Alerts - {environment_name}"
    "active_days": "Monday" #See "Custom alarm tags" above (default is "NOT_SET")
    "do_not_alert_before": "0700" #See "Custom alarm tags" above (default is "NOT_SET")
    "do_not_alert_after": "1900" #See "Custom alarm tags" above (default is "NOT_SET")
    "icon_override": ":aws:" #Slack text to create icon emoji for the message, default is to work out an icon from severity and notification_type
    "slack_channel_override": "aws-dataworks-critical-alerts" #Slack channel name for the message, default is to work out an icon from severity and notification_type
    "log_with_here": "true" #If "true" then adds @here to the slack message
    "title_text": "HTME Export completed" #Custom text for the alert, defaults to "NOT_SET"
}
```

The defaults allow for SQS messages with incorrect format to still log to slack so we can see where there are issues.

You can also pass in custom fields to appear in the alert using the below format:

```
...
    "custom_elements": [
        {
            "key": "element_name_1",
            "value": "element_value_1"
        },
        {
            "key": "element_name_2",
            "value": "element_value_2"
        },
        ...
    ]
...
```

## Tests

The module uses tox to execute its unit tests using pytest runner. In order to run, you need to `pip install tox` first and then simply run `tox` from the root level.

This will install all the required packages and run all the unit tests for the module.
