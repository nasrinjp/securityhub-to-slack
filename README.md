# securityhub-to-slack
Notify findings of Security Hub to Slack channel.  
  
References:  
https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cloudwatch-events.html#securityhub-cwe-all-findings

## Prerequisite

### Environment

* Python 3.8
* AWS SAM

### Specify SSM Parameter Store for Slack URL
The following commands are examples.  

```
aws ssm put-parameter \
    --name "/slack_url/workspacename/channel" \
    --type "SecureString" \
    --value "https://xxx" \
    --overwrite
```

### Variables examples

* parameter_store_name_for_slack_url
    * Specify the name of SSM Parameter Store that contains Slack URL.
    * Example: slack_url/workspacename/channel

## Build
To build, execute the following command.  

```
sam build
```

## Deploy
To deploy, execute the following command.  

```
sam deploy --guided
```