# CrowdStrike ECR Auto-Onboarding - Removal Guide

> **Back to**: [README.md](README.md) | **Setup Guide**: [Quick Start](README.md#quick-start) | **Technical Details**: [EXTERNAL_ID_FLOW.md](EXTERNAL_ID_FLOW.md)

This guide provides instructions for completely removing the ECR Auto-Onboarding solution from your AWS environment.

## ⚠️ Important Considerations

**Before Removal:**
- ECR repositories will no longer be automatically onboarded to Container Security
- Existing ECR registrations in Container Security will remain (you may want to remove them manually)
- CSPM functionality will continue to work normally after role cleanup

**Impact Assessment:**
- Review existing ECR registrations in CrowdStrike Container Security console
- Decide if you want to keep any manual registrations
- Ensure you have alternative ECR onboarding processes if needed

## Removal Steps

### Step 1: Remove Lambda Function and Infrastructure

#### Option A: Delete CloudFormation Stack (Recommended)

```bash
# Delete the entire stack and all associated resources
aws cloudformation delete-stack --stack-name ecr-auto-onboard

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name ecr-auto-onboard

# Verify deletion
aws cloudformation describe-stacks --stack-name ecr-auto-onboard 2>/dev/null || echo "Stack successfully deleted"
```

#### Option B: Manual Resource Cleanup

If CloudFormation deletion fails, remove resources manually:

```bash
# Delete Lambda function
aws lambda delete-function --function-name ecr-auto-onboard-ecr-onboard

# Delete EventBridge rule
aws events delete-rule --name ecr-auto-onboard-ECRDiscoveryScheduleRule

# Delete SNS topic (if created)
aws sns delete-topic --topic-arn "arn:aws:sns:region:account:ecr-auto-onboard-notifications"

# Delete CloudWatch log group
aws logs delete-log-group --log-group-name /aws/lambda/ecr-auto-onboard-ecr-onboard

# Delete IAM role and policies
aws iam delete-role-policy --role-name ecr-auto-onboard-ECROnboardLambdaRole --policy-name ecr-auto-onboard-LambdaPolicy
aws iam delete-role --role-name ecr-auto-onboard-ECROnboardLambdaRole
```

### Step 2: Clean Up S3 Deployment Bucket

```bash
# List objects in the bucket
aws s3 ls s3://your-ecr-deploy-bucket/

# Delete Lambda deployment package
aws s3 rm s3://your-ecr-deploy-bucket/ecr-lambda-source.zip

# Delete bucket (if no other objects)
aws s3 rb s3://your-ecr-deploy-bucket
```

### Step 3: Remove CrowdStrike API Credentials

#### Option A: Delete Secrets Manager Secret

```bash
# Schedule secret deletion (7-day recovery period)
aws secretsmanager delete-secret \
  --secret-id "crowdstrike/ecr-auto-onboard/credentials" \
  --recovery-window-in-days 7

# Or force immediate deletion (cannot be recovered)
aws secretsmanager delete-secret \
  --secret-id "crowdstrike/ecr-auto-onboard/credentials" \
  --force-delete-without-recovery
```

#### Option B: Remove SSM Parameters (if used)

```bash
# Remove API credentials from Parameter Store
aws ssm delete-parameter --name "/crowdstrike/ecr-auto-onboard/client-id"
aws ssm delete-parameter --name "/crowdstrike/ecr-auto-onboard/client-secret"
aws ssm delete-parameter --name "/crowdstrike/ecr-auto-onboard/slack-webhook" # if configured
```

### Step 4: Revert CSPM Role Changes

**Important**: Only do this if you don't need Container Security access to your CSPM roles for other purposes.

#### Option A: Automated Reversion Script

Save this as `revert-cspm-role.sh`:

```bash
#!/bin/bash
# Revert CSPM role to original configuration

ROLE_NAME="${1}"

if [ -z "$ROLE_NAME" ]; then
    echo "Usage: $0 <CSPM_ROLE_NAME>"
    echo "Example: $0 CrowdStrikeCSPMReader-gt7elswu7hug"
    exit 1
fi

echo "Reverting CSPM role: $ROLE_NAME"

# Get current trust policy
CURRENT_POLICY=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.AssumeRolePolicyDocument' --output json)

# Extract CSPM external ID
CSPM_EXTERNAL_ID=$(echo "$CURRENT_POLICY" | jq -r '.Statement[] | select(.Principal.AWS | contains("CrowdStrikeCSPMConnector")) | .Condition.StringEquals."sts:ExternalId"')

if [ "$CSPM_EXTERNAL_ID" = "null" ] || [ -z "$CSPM_EXTERNAL_ID" ]; then
    echo "❌ Could not find CSPM external ID"
    exit 1
fi

# Create original CSPM-only trust policy
cat > /tmp/original_cspm_policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "$CSMP_EXTERNAL_ID"
                }
            }
        }
    ]
}
EOF

# Update role trust policy
aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document file:///tmp/original_cspm_policy.json

# Remove ECR permissions (if they weren't there originally)
echo "Note: You may want to remove ECR permissions if they weren't originally attached:"
echo "aws iam detach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"

# Cleanup
rm -f /tmp/original_cspm_policy.json

echo "✅ CSPM role reverted to original configuration"
```

#### Option B: Manual Trust Policy Reversion

1. **Get current external ID**:
   ```bash
   aws iam get-role --role-name YOUR_CSPM_ROLE_NAME --query 'Role.AssumeRolePolicyDocument'
   ```

2. **Update trust policy to CSPM-only**:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Principal": {
                   "AWS": "arn:aws:iam::292230061137:role/CrowdStrikeCSPMConnector"
               },
               "Action": "sts:AssumeRole",
               "Condition": {
                   "StringEquals": {
                       "sts:ExternalId": "YOUR_ORIGINAL_CSPM_EXTERNAL_ID"
                   }
               }
           }
       ]
   }
   ```

3. **Remove ECR permissions** (if they weren't originally attached):
   ```bash
   aws iam detach-role-policy --role-name YOUR_CSPM_ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
   ```

### Step 5: Clean Up Container Security Registrations

#### Option A: Remove All Auto-Created Registrations

⚠️ **Warning**: This will remove ECR registrations from Container Security. Image assessment will stop for these registries.

```bash
# List current ECR registrations
aws logs filter-log-events \
  --log-group-name /aws/lambda/ecr-auto-onboard-ecr-onboard \
  --filter-pattern "Registry ID" \
  --start-time $(date -d '30 days ago' +%s)000

# Or check CrowdStrike Container Security console:
# Go to Container Security > Registries
# Look for registries with aliases starting with "Auto-"
```

**Manual Removal in CrowdStrike Console**:
1. Go to Container Security > Registries
2. Find registries created by auto-onboarding (usually have "Auto-" prefix)
3. Delete registries you no longer need

#### Option B: Keep Existing Registrations

If you want to keep the ECR registrations but stop auto-onboarding:
- Only complete Steps 1-3 above
- Leave Container Security registrations as-is
- They will continue to work but won't be automatically managed

## Verification Steps

After removal, verify everything is cleaned up:

### 1. AWS Resources

```bash
# Verify Lambda is deleted
aws lambda get-function --function-name ecr-auto-onboard-ecr-onboard 2>/dev/null && echo "❌ Lambda still exists" || echo "✅ Lambda deleted"

# Verify CloudFormation stack is deleted
aws cloudformation describe-stacks --stack-name ecr-auto-onboard 2>/dev/null && echo "❌ Stack still exists" || echo "✅ Stack deleted"

# Verify S3 bucket is empty/deleted
aws s3 ls s3://your-ecr-deploy-bucket/ 2>/dev/null && echo "❌ Bucket still has objects" || echo "✅ Bucket cleaned"

# Verify secrets are deleted
aws secretsmanager describe-secret --secret-id "crowdstrike/ecr-auto-onboard/credentials" 2>/dev/null && echo "❌ Secret still exists" || echo "✅ Secret deleted"
```

### 2. CSPM Role Configuration

```bash
# Verify CSPM role is reverted
aws iam get-role --role-name YOUR_CSPM_ROLE_NAME --query 'Role.AssumeRolePolicyDocument' | grep -q "CrowdStrikeCustomerRegistryAssessmentRole" && echo "❌ Container Security access still configured" || echo "✅ CSPM role reverted"
```

### 3. Container Security

- Check CrowdStrike Container Security console
- Verify no unwanted ECR registrations remain
- Confirm CSPM functionality is unaffected

## Recovery Options

If you need to restore the solution:

1. **Re-run the setup script**: `./setup-cspm-role.sh`
2. **Re-deploy CloudFormation**: Use the same parameters as original deployment
3. **Restore API credentials**: Create new Secrets Manager secret with CrowdStrike API credentials

## Support

If you encounter issues during removal:

1. Check CloudWatch logs for any remaining Lambda executions
2. Verify IAM permissions for deletion operations
3. Contact CrowdStrike support if Container Security registrations cannot be removed
4. Use AWS support for infrastructure cleanup issues

## Complete Removal Checklist

- [ ] CloudFormation stack deleted
- [ ] Lambda function removed
- [ ] S3 deployment bucket cleaned
- [ ] Secrets Manager secret deleted
- [ ] CSPM role trust policy reverted
- [ ] ECR permissions removed (if added)
- [ ] Container Security registrations reviewed/removed
- [ ] Verification steps completed
- [ ] CSPM functionality confirmed working

---

**Note**: This removal process is designed to be thorough and reversible. Keep a backup of your configurations if you plan to re-implement the solution later.