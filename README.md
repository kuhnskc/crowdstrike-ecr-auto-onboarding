# CrowdStrike ECR Auto-Onboarding & Cleanup

Automatically discovers and registers AWS ECR registries with CrowdStrike Container Security for image assessment, and intelligently manages registry cleanup using your existing CSPM roles.

## Documentation

- **[Setup Guide](#quick-start)** - Complete setup instructions
- **[FAQ](#frequently-asked-questions)** - Common questions and answers
- **[EXTERNAL_ID_FLOW.md](EXTERNAL_ID_FLOW.md)** - Technical implementation details
- **[REMOVAL_GUIDE.md](REMOVAL_GUIDE.md)** - Complete uninstall instructions

## Key Features

- **Uses Existing CSPM Roles** - Leverages your existing CrowdStrike CSPM roles (no separate ECR roles needed)
- **One-Time Customer Setup** - Simple script updates CSPM role trust policy for Container Security access
- **Dynamic IAM Role Discovery** - Automatically discovers IAM roles from CSPM registration (no hardcoded templates)
- **Multi-Account Support** - Works across all accounts visible to CrowdStrike Asset Explorer
- **Repository-to-Registry Mapping** - Intelligently groups repositories into unique registries
- **Smart Cleanup** - Automatically removes stale ECR registries based on business rules
- **Dry Run Mode** - Test thoroughly before making any actual registrations or deletions
- **Scheduled & On-Demand** - Runs automatically 3x daily, plus manual execution
- **Comprehensive Monitoring** - CloudWatch dashboard, logs, and alarms
- **Multi-Channel Notifications** - Email (SNS) and Slack integration
- **Production-Ready** - Enterprise logging, error handling, and security

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

## External ID Flow (No Manual Configuration Required)

**Key Point**: Customers do **NOT** need to provide external IDs to the Lambda. The process is fully automated:

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  1. Customer Setup  │    │  2. Lambda Runtime  │    │  3. ECR Registration│
│                     │    │                     │    │                     │
│  • Update CSPM role │    │  • Query CSPM API   │    │  • Use discovered   │
│    trust policy     │───▶│  • Discover external│───▶│    external ID      │
│  • Same external ID │    │    ID automatically │    │  • Register ECR     │
│    for both services│    │  • No configuration │    │    with Container   │
│                     │    │    needed           │    │    Security         │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

**What Customers Need to Know:**
- **No external ID configuration** required in Lambda deployment
- **Automatic discovery** from existing CSPM registration
- **Same external ID** works for both CSPM and Container Security
- **Zero manual coordination** between role setup and Lambda deployment

> **Technical Details**: See [EXTERNAL_ID_FLOW.md](EXTERNAL_ID_FLOW.md) for detailed technical implementation

## Prerequisites

1. **CrowdStrike CSPM** - AWS accounts must be registered with CrowdStrike CSPM
2. **AWS Permissions** - Deploy CloudFormation with IAM capabilities
3. **CrowdStrike API Credentials** - Client ID and Client Secret with appropriate scopes
4. **CSPM Role Setup** - One-time update to enable Container Security access

## Quick Start

### Step 1: Prepare CSPM Roles

**Important**: This one-time setup enables your existing CSMP roles to work with ECR auto-onboarding.

#### Option A: Automated Setup (Recommended)

Download and run our setup script in AWS CloudShell:

```bash
# Download the setup script
wget https://raw.githubusercontent.com/kuhnskc/crowdstrike-ecr-auto-onboarding/main/setup-cspm-role.sh
chmod +x setup-cspm-role.sh

# Run setup (auto-discovers CSPM role)
./setup-cspm-role.sh

# Or specify role name
./setup-cspm-role.sh CrowdStrikeCSPMReader-gt7elswu7hug
```

#### Option B: Manual Setup

1. **Find your CSMP role**:
   ```bash
   aws iam list-roles --query 'Roles[?contains(RoleName, `CrowdStrike`) && contains(RoleName, `CSPM`)].RoleName' --output table
   ```

2. **Get current external ID**:
   ```bash
   aws iam get-role --role-name YOUR_CSPM_ROLE_NAME --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals."sts:ExternalId"' --output text
   ```

3. **Update trust policy** to add Container Security access:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Principal": {
                   "AWS": [
                       "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector",
                       "arn:aws:iam::292230061137:role/CrowdStrikeCustomerRegistryAssessmentRole"
                   ]
               },
               "Action": "sts:AssumeRole",
               "Condition": {
                   "StringEquals": {
                       "sts:ExternalId": "YOUR_EXISTING_CSPM_EXTERNAL_ID"
                   }
               }
           }
       ]
   }
   ```

4. **Add ECR permissions** (if not already present):
   ```bash
   aws iam attach-role-policy --role-name YOUR_CSPM_ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
   ```

### Step 2: Deploy Lambda Function

**Important**: No external ID configuration needed! The Lambda automatically discovers external IDs from your CSPM registration.

#### Method 1: One-Click CloudFormation

[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=https://raw.githubusercontent.com/kuhnskc/crowdstrike-ecr-auto-onboarding/main/cloudformation/ecr-onboard-production.yaml)

#### Method 2: AWS CLI Deployment

```bash
# 1. Create S3 bucket for deployment
aws s3 mb s3://your-ecr-deploy-bucket

# 2. Package and upload Lambda code
zip -r ecr-lambda-source.zip src/lambda/*
aws s3 cp ecr-lambda-source.zip s3://your-ecr-deploy-bucket/

# 3. Create Secrets Manager secret with your CrowdStrike API credentials
aws secretsmanager create-secret \
  --name "crowdstrike/ecr-auto-onboard/credentials" \
  --secret-string '{"client_id":"YOUR_CLIENT_ID","client_secret":"YOUR_CLIENT_SECRET"}'

# 4. Deploy CloudFormation stack
aws cloudformation deploy \
  --template-file cloudformation/ecr-onboard-production.yaml \
  --stack-name ecr-auto-onboard \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    S3BucketName="your-ecr-deploy-bucket" \
    CrowdStrikeSecretsArn="arn:aws:secretsmanager:region:account:secret:crowdstrike/ecr-auto-onboard/credentials-XXXXXX" \
    NotificationEmail="your-email@example.com" \
    EnableDryRunMode=false
```

### Step 3: Verify Setup

```bash
# Test the Lambda function
aws lambda invoke --function-name ecr-auto-onboard-ecr-onboard response.json
cat response.json

# Check CloudWatch logs
aws logs tail /aws/lambda/ecr-auto-onboard-ecr-onboard --follow

# Monitor in CrowdStrike Console
# Go to Container Security > Registries to see auto-registered ECR registries
```

## Frequently Asked Questions

### External ID & Configuration

**Q: Do I need to provide the external ID when deploying the Lambda?**
A: **No!** The Lambda automatically discovers external IDs from your CSPM registration. No manual configuration needed.

**Q: How does the Lambda know which external ID to use?**
A: The Lambda queries the CrowdStrike CSPM API (`/cloud-security-registration-aws/entities/account/v1`) which returns the external ID for each registered account. This is the same external ID you use in your CSPM role trust policy.

**Q: What if I have multiple AWS accounts with different external IDs?**
A: Perfect! The Lambda discovers each account's external ID individually and uses the correct one for each ECR registry registration.

**Q: Can I override the external ID discovery?**
A: The current version uses automatic discovery only. This ensures consistency with your CSPM registration and prevents configuration errors.

**Q: How do I verify the Lambda is using the correct external ID?**
A: Check CloudWatch logs. The Lambda logs show: `External ID: d704125f265d436482e6ce36ca5be581` for each account it processes.

### Role Setup

**Q: Do I need separate ECR roles or can I use my CSPM roles?**
A: **Use your existing CSPM roles!** Just add the Container Security principal to the trust policy. No separate ECR roles needed.

**Q: Will this break my existing CSPM functionality?**
A: **No!** Adding the Container Security principal to your CSPM role trust policy is additive - it doesn't affect CSPM operations.

**Q: What if I have accounts that aren't registered with CSPM?**
A: The Lambda only processes accounts registered with CSPM. Manual ECR registrations in non-CSPM accounts are ignored (protected by the cleanup logic).

> **Removal Instructions**: See [REMOVAL_GUIDE.md](REMOVAL_GUIDE.md) for complete uninstall procedures

## Configuration Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| **S3BucketName** | S3 bucket containing Lambda deployment package | - | Yes |
| **CrowdStrikeSecretsArn** | ARN of Secrets Manager secret with API credentials | - | Yes |
| **NotificationEmail** | Email for SNS notifications | - | No |
| **EnableDryRunMode** | Test mode (no actual changes) | false | No |
| **EnableCleanup** | Enable automatic cleanup of stale registries | true | No |
| **CleanupOfflineDays** | Days threshold for cleanup (offline registries) | 7 | No |
| **ScheduleExpression** | Cron expression for execution schedule | cron(0 6,12,18 * * ? *) | No |

## ECR Registry Cleanup Logic

The solution implements intelligent cleanup with 3-rule business logic:

| Account in CSPM? | ECR in Image Assessment? | Registry State | Action | Reason |
|------------------|--------------------------|---------------|---------|--------|
| No | Yes | Any | **IGNORE** | Manual registration - don't touch |
| Yes | No | N/A | **ONBOARD** | Missing registry - auto-register |
| Yes | Yes | Offline 7+ days | **DELETE** | Stale registry - cleanup |
| Yes | Yes | Active/Recent | **KEEP** | Working registry - maintain |

**Safety Features:**
- **Manual Registration Protection**: Never touches registries from non-CSPM accounts
- **Configurable Timeouts**: Adjustable days threshold for cleanup
- **Dry Run Support**: Test mode for safe validation
- **Comprehensive Logging**: Full audit trail of all decisions

## Monitoring & Operations

### CloudWatch Dashboard

The deployment creates a comprehensive dashboard showing:
- Lambda execution metrics (duration, invocations, errors)
- Recent logs and error patterns
- Registration and cleanup activity
- Performance trends

### Manual Testing

```bash
# Test current function
aws lambda invoke --function-name ecr-auto-onboard-ecr-onboard response.json
cat response.json

# Test with dry run override
echo '{"dry_run": true}' | base64  # eyJkcnlfcnVuIjogdHJ1ZX0K
aws lambda invoke \
  --function-name ecr-auto-onboard-ecr-onboard \
  --payload eyJkcnlfcnVuIjogdHJ1ZX0K \
  response.json

# Check logs
aws logs tail /aws/lambda/ecr-auto-onboard-ecr-onboard --follow
```

### Troubleshooting

#### Common Issues

**1. "No ECR repositories found"**
- Verify AWS accounts are registered with CrowdStrike CSPM
- Check Asset Explorer shows ECR repositories

**2. "Failed to get CSPM credentials"**
- Verify CSPM registration is active
- Check IAM role exists and is accessible

**3. "Registration failed: failed to validate registry credential"**
- Verify CSPM role trust policy includes Container Security principal
- Run setup script to fix role configuration
- Check ECR permissions are attached to role

**4. Lambda timeout errors**
- Increase Lambda timeout in CloudFormation parameters
- Check if large number of repositories causing delays

#### Debug Commands

```bash
# Check CSPM role configuration
aws iam get-role --role-name YOUR_CSPM_ROLE_NAME

# List current ECR registrations
aws logs filter-log-events \
  --log-group-name /aws/lambda/ecr-auto-onboard-ecr-onboard \
  --filter-pattern "Found.*ECR registrations"

# Test manual ECR registration (using test script kept for debugging)
./test_ecr_onboard.sh YOUR_ROLE_ARN YOUR_EXTERNAL_ID
```

## Security Considerations

- **Least Privilege**: Lambda uses minimal IAM permissions
- **Secure Credentials**: API credentials stored in AWS Secrets Manager
- **External ID**: Each role uses unique external ID for secure cross-account access
- **Audit Trail**: All operations logged to CloudWatch
- **Network Security**: Lambda runs in AWS managed environment

## API Integration

The solution integrates with these CrowdStrike APIs:

- **Authentication**: `/oauth2/token`
- **Asset Explorer**: `/cloud-security-assets/queries/resources/v1` (ECR discovery)
- **CSPM Registration**: `/cloud-security-registration-aws/entities/account/v1` (IAM credentials)
- **Container Security**:
  - `/container-security/queries/registries/v1` (existing registrations)
  - `/container-security/entities/registries/v1` (registration/cleanup)

## Project Structure

```
ecr-integration-enhanced/
├── cloudformation/
│   └── ecr-onboard-production.yaml          # Complete CloudFormation template
├── src/
│   └── lambda/
│       ├── ecr_auto_onboard_production.py   # Main Lambda function
│       ├── requirements.txt                 # Python dependencies
│       └── [dependencies]/                  # Packaged Python libraries
├── setup-cspm-role.sh                       # Customer CSPM role setup script
├── README.md                                # This comprehensive documentation
├── EXTERNAL_ID_FLOW.md                      # Technical external ID flow diagram
├── REMOVAL_GUIDE.md                         # Complete removal instructions
├── ecr-lambda-source.zip                    # Pre-packaged Lambda deployment
└── testing-archive/                         # Archived development/test files
```

### Key Files

| File | Purpose | For Customer |
|------|---------|--------------|
| **setup-cspm-role.sh** | Updates CSPM roles for Container Security access | Required |
| **README.md** | Complete setup and usage documentation | Required |
| **ecr-onboard-production.yaml** | CloudFormation deployment template | Required |
| **ecr_auto_onboard_production.py** | Main Lambda function source code | Reference |
| **[EXTERNAL_ID_FLOW.md](EXTERNAL_ID_FLOW.md)** | Technical implementation details | Reference |
| **[REMOVAL_GUIDE.md](REMOVAL_GUIDE.md)** | Complete uninstall instructions | As needed |
| **ecr-lambda-source.zip** | Pre-built deployment package | Required |

## Support

For issues or questions:
1. Check CloudWatch logs for detailed error information
2. Verify CSPM role configuration with setup script
3. Test with dry run mode to isolate issues
4. **Report issues**: [GitHub Issues](https://github.com/kuhnskc/crowdstrike-ecr-auto-onboarding/issues)
5. Contact CrowdStrike support with log details

## Additional Resources

- **[Project Repository](https://github.com/kuhnskc/crowdstrike-ecr-auto-onboarding)** - Source code and latest releases
- **[Technical Flow Diagram](EXTERNAL_ID_FLOW.md)** - Detailed external ID implementation
- **[Removal Instructions](REMOVAL_GUIDE.md)** - Complete uninstall procedures

## License

This project is licensed under the terms specified by CrowdStrike.