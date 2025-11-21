# CrowdStrike ECR Auto-Onboarding

Automatically discovers and registers AWS ECR registries with CrowdStrike Container Security for image assessment, and intelligently manages registry cleanup using your existing CSPM roles.

## Key Features

- **Uses Existing CSPM Roles** - Leverages your existing CrowdStrike CSPM roles (no separate ECR roles needed)
- **Dynamic IAM Role Discovery** - Automatically discovers IAM roles from CSPM registration (no hardcoded templates)
- **Multi-Account Support** - Works across all accounts visible to CrowdStrike Asset Explorer
- **Smart Cleanup** - Automatically removes stale ECR registries based on business rules
- **Scheduled & On-Demand** - Runs automatically 3x daily, plus manual execution
- **Comprehensive Monitoring** - CloudWatch dashboard, logs, and alarms

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Asset         │    │   CSPM Role      │    │   Container     │
│   Explorer      │────│   (Enhanced)     │────│   Security      │
│   (ECR Repos)   │    │   + ECR Access   │    │   (Registry)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │   Lambda Function   │
                    │   (Auto-Onboard)    │
                    └─────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │   CloudWatch Events │
                    │   (Scheduled 3x/day)│
                    └─────────────────────┘
```

**How It Works:**
1. **Customer Setup**: One-time CSPM role update for Container Security access
2. **Scheduled Discovery**: Lambda runs 3x daily (6AM, 12PM, 6PM)
3. **Dynamic Discovery**: Queries CSPM API for actual IAM roles and external IDs
4. **Automatic Registration**: Registers missing ECR registries using discovered credentials

## Prerequisites

1. **CrowdStrike CSPM** - AWS accounts must be registered with CrowdStrike CSPM
2. **AWS Permissions** - Deploy CloudFormation with IAM capabilities
3. **CrowdStrike API Credentials** - Client ID and Client Secret with appropriate scopes

## Quick Start

### Step 1: Update CSPM Roles

Download and run our setup script in AWS CloudShell:

```bash
# Download the setup script
wget https://raw.githubusercontent.com/kuhnskc/crowdstrike-ecr-auto-onboarding/main/setup-cspm-role.sh
chmod +x setup-cspm-role.sh

# Run setup (auto-discovers CSPM role)
./setup-cspm-role.sh

# Or specify role name if you have multiple
./setup-cspm-role.sh CrowdStrikeCSPMReader-ABC123XYZ
```

This script adds Container Security access to your existing CSPM role trust policy.

### Step 2: Deploy Lambda Function

#### Prerequisites

```bash
# 1. Create S3 bucket for deployment
S3_BUCKET_NAME="ecr-deploy-bucket-$(date +%s)"
aws s3 mb s3://$S3_BUCKET_NAME
echo "S3 Bucket: $S3_BUCKET_NAME"

# 2. Download and upload Lambda package
wget https://github.com/kuhnskc/crowdstrike-ecr-auto-onboarding/releases/latest/download/ecr-lambda-source.zip
aws s3 cp ecr-lambda-source.zip s3://$S3_BUCKET_NAME/

# 3. Create CrowdStrike API credentials secret
aws secretsmanager create-secret \
  --name "crowdstrike/ecr-auto-onboard/credentials" \
  --secret-string '{"client_id":"YOUR_CLIENT_ID","client_secret":"YOUR_CLIENT_SECRET"}'

# 4. Get values for CloudFormation
CROWDSTRIKE_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id "crowdstrike/ecr-auto-onboard/credentials" --query 'ARN' --output text)
echo "Secret ARN: $CROWDSTRIKE_SECRET_ARN"
echo "S3 Bucket: $S3_BUCKET_NAME"
```

#### Option A: Deploy via AWS Console

```bash
# Download CloudFormation template
wget https://raw.githubusercontent.com/kuhnskc/crowdstrike-ecr-auto-onboarding/main/cloudformation/ecr-onboard-production.yaml
```

1. Go to [CloudFormation Console](https://console.aws.amazon.com/cloudformation/home)
2. Click "Create Stack" → "With new resources"
3. Choose "Upload a template file" and select the downloaded YAML
4. Fill in parameters:
   - **S3BucketName**: Use the bucket name from above
   - **CrowdStrikeSecretsArn**: Use the ARN from above
   - **NotificationEmail**: Your email for alerts
   - **EnableDryRunMode**: false

#### Option B: Deploy via AWS CLI

```bash
# Deploy CloudFormation stack
aws cloudformation deploy \
  --template-file ecr-onboard-production.yaml \
  --stack-name ecr-auto-onboard \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    S3BucketName="$S3_BUCKET_NAME" \
    CrowdStrikeSecretsArn="$CROWDSTRIKE_SECRET_ARN" \
    NotificationEmail="your-email@example.com" \
    EnableDryRunMode=false
```

### Step 3: Test Setup

```bash
# Test the Lambda function
aws lambda invoke --function-name ecr-auto-onboard-ecr-onboard response.json
cat response.json
```

#### Success Output
```json
{
  "statusCode": 200,
  "body": "{
    \"discovered_registries\": 3,
    \"new_registrations\": 2,
    \"existing_registrations\": 1,
    \"failed_registrations\": 0,
    \"errors\": []
  }"
}
```

#### Troubleshooting

**Authentication Failed**: Verify API credentials and CSPM role setup
**No ECR Found**: Check CSPM registration and Asset Explorer

```bash
# Check logs for details
aws logs tail /aws/lambda/ecr-auto-onboard-ecr-onboard --follow
```

## ECR Registry Cleanup Logic

| Account in CSPM? | ECR in Container Security? | Registry State | Action |
|------------------|----------------------------|---------------|---------|
| No | Yes | Any | **IGNORE** (Manual registration) |
| Yes | No | N/A | **ONBOARD** (Missing registry) |
| Yes | Yes | Offline 7+ days | **DELETE** (Stale registry) |
| Yes | Yes | Active/Recent | **KEEP** (Working registry) |

## Configuration Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| **S3BucketName** | S3 bucket with Lambda package | - | Yes |
| **CrowdStrikeSecretsArn** | Secrets Manager ARN with API credentials | - | Yes |
| **NotificationEmail** | Email for SNS notifications | - | No |
| **EnableDryRunMode** | Test mode (no actual changes) | false | No |
| **EnableCleanup** | Enable automatic cleanup | true | No |
| **CleanupOfflineDays** | Days threshold for cleanup | 7 | No |
| **ScheduleExpression** | Cron schedule | cron(0 6,12,18 * * ? *) | No |

## Monitoring & Operations

### CloudWatch Dashboard
The deployment creates a comprehensive dashboard showing Lambda metrics, logs, and registration activity.

### Manual Testing
```bash
# Production test
aws lambda invoke --function-name ecr-auto-onboard-ecr-onboard response.json

# Dry run test (no changes) - encode payload and invoke
PAYLOAD=$(echo '{"dry_run": true}' | base64)
aws lambda invoke \
  --function-name ecr-auto-onboard-ecr-onboard \
  --payload $PAYLOAD \
  response.json
```

## Project Structure

```
ecr-integration-enhanced/
├── cloudformation/
│   └── ecr-onboard-production.yaml          # CloudFormation template
├── src/
│   └── lambda/
│       ├── ecr_auto_onboard_production.py   # Main Lambda function
│       ├── requirements.txt                 # Python dependencies
│       └── [dependencies]/                  # Packaged Python libraries
├── setup-cspm-role.sh                       # CSPM role setup script
├── README.md                                # This documentation
└── ecr-lambda-source.zip                    # Pre-packaged Lambda deployment
```

## Disclaimer

This project was co-authored with Claude AI and is an **unofficial, unsupported** tool. Use at your own risk. While designed to work with CrowdStrike products, this is not an official CrowdStrike solution and comes with no warranties or support guarantees.

**Report Issues**: [GitHub Issues](https://github.com/kuhnskc/crowdstrike-ecr-auto-onboarding/issues)