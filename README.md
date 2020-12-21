# aws-cloudwatch-alerting
Lambda function to send CloudWatch alerts to Slack written in python 3.8

## Basic functionality

The lambda reacts to given SNS messages, looks at the payload and generates a slack message payload which it then posts to a slack webhook URL.

## Message structure

The lambda will react to alerts sent from SNS to whatever topics it is subscribed to. The SNS message stucture can be found at https://docs.aws.amazon.com/lambda/latest/dg/with-sns.html.

## Different message types

The app will look at the message payload (`$.Records[0].SNS.Message`) and react differently depending on different fields that are present. These scenarios are desribed below.

If none of these scenarios are matched, then there is a fallback scenario which will which send a message with the phrase `Unindentified message` as the title the dumped payload as well.

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

If the message has the `detail-type` field and the field contains `GuardDuty Finding` it is a guard duty notification. If this is the case then a notification is logged with the text `AWS GuardDuty Finding Type` and a URL is consructed to go directly to the finding in the AWS console.

### Configuration notifications

If the message has the `configRuleName` field it is a configuration notification. If this is the case then a notification is logged with the text `AWS Config Compliance Change detected` and a URL is consructed to go directly to the finding in the AWS console.

### Cloudwatch event notifications

If the message has the `messageType` field it is a cloudwatch event notification. If this is the case then a notification is logged with the text `AWS Config CloudWatch Event` and a URL is consructed to go directly to the finding in the AWS console. Details of the event are pulled out and provided as extra information in the slack message.

### Cloudwatch alarm notifications

If the message has the `AlarmName` field it is a cloudwatch alarm notification. If this is the case their are two sub scenarios based on the message itself.

#### Prowler alarms

If the message has the `Namespace` field and its value is set to `Prowler/Monitoring` then the message is assumed to be from the Prowler monitoring that is set up. In this case, the message is processed with a title of the name of the monitoring alert triggered an a URL to go to the alert directly is generated and set in the slack message.

#### Custom alarms

Without the `Namespace` field or if it is set to a different value, then the message is treated differently. The title will be set as the following:

* `{icon} *{environment_name.upper()}*: "_{alarm_name}_" in {region}'`

The `region` and `alarm_name` fields come directly from the message and `environment_name` is from the `AWS_ENVIRONMENT_NAME` environment variable.

The icon is set from the severity and the type of notification. These values also set the channel that the slack notification goes to and they are logged in the message as well. Their values are retrieved from the tags on the cloudwatch alarm itself and are detailed in the section below.

#### Custom alarm tags

The following tags are retrieved from the cloudwatch alarm and each one has a default in case it is not present:

* `severity` -> this is used to determine the icon used for the alarm and the channel it goes to, supported values are `Low`, `Medium`, `High` and `Critical`. Default is `Medium`

* `notification_type` -> this is used to determine the icon used for the alarm and the channel it goes to, supported values are `Information`, `Warning` and `Error`. Default is `Warning`

* `active_days` -> if set, this will mean any alarm on a day that is not present in this list will be suppressed and no notification will be sent to slack. The format is a comma delimited list of ini-capped weekday names, i.e. `Monday,Tuesday`. Default is `NOT_SET`

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
* `AWS_ENVIRONMENT` (required if `USE_AWS_SLACK_CHANNELS` is `true`) -> The environment name the AWS alarms will be coming from, should be a human readable name

If this application is going to be used to receive anything other than `app` or `custom cloudwatch alarm` notification types (see above) then the following must also be provided for it to work

* `STATUS_SLACK_WEBHOOK_URL` (required if non app/custom alarm notications needed) -> The slack URL to send these notifications to
* `STATUS_SLACK_CHANNEL` (required if non app/custom alarm notications needed) -> The name of the slack channel to send these notifications to
* `STATUS_SLACK_USERNAME` (required if non app/custom alarm notications needed) -> The username used for posting these notifications, can be anything
* `STATUS_SLACK_ICON_EMOJI` (required if non app/custom alarm notications needed) -> The icon name used for these notifications i.e. `:aws:`

If this application is going to be used to receive `app` notification types (see above) then the following must be provided for it to work

* `APP_INFO_SLACK_WEBHOOK_URL` (required if app notications needed) -> The slack URL to send app notifications to
* `APP_INFO_SLACK_CHANNEL` (required if app notications needed) -> The name of the slack channel to send app notifications to
* `APP_INFO_SLACK_USERNAME` (required if app notications needed) -> The username used for posting app notifications, can be anything
* `APP_INFO_SLACK_ICON_EMOJI` (required if app notications needed) -> The icon name used for app notifications i.e. `:aws:`

## Tests

The module uses tox to execute its unit tests using pytest runner. In order to run, you need to `pip install tox` first and then simply run `tox` from the root level.

This will install all the required packages and run all the unit tests for the module.
